#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import hvac
import pytest
import yaml
from juju.action import Action
from juju.errors import JujuError
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

import tests.integration.helpers as helpers
from tests.integration.helpers import (
    get_leader_unit,
)

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_REVISION = 263
VAULT_KV_REQUIRER_1_APPLICATION_NAME = "vault-kv-requirer-a"
VAULT_KV_REQUIRER_2_APPLICATION_NAME = "vault-kv-requirer-b"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
VAULT_PKI_REQUIRER_REVISION = 93
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
MINIO_APPLICATION_NAME = "minio"
AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
MINIO_CONFIG = {
    "access-key": MINIO_S3_ACCESS_KEY,
    "secret-key": MINIO_S3_SECRET_KEY,
}

NUM_VAULT_UNITS = 3
CURRENT_TRACK_FIRST_STABLE_REVISION = 259
CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.16/stable"


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


@pytest.fixture(scope="module")
async def deployed_vault(ops_test: OpsTest, request: pytest.FixtureRequest):
    """Deploy Vault."""
    assert ops_test.model
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
    await ops_test.model.deploy(
        charm_path,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
        series="jammy",
        num_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )


@pytest.fixture(scope="module")
async def active_vault(
    ops_test: OpsTest, deployed_vault: Dict[str, Path | str]
) -> Tuple[int, str, str]:
    """Initialize, unseal, and authorize Vault for an independent test module."""
    assert ops_test.model
    leader_unit_index, root_token, unseal_key = await initialize_vault_leader(
        ops_test, APPLICATION_NAME
    )
    unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
    async with ops_test.fast_forward(fast_interval="60s"):
        unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
        await helpers.wait_for_status_message(
            ops_test=ops_test,
            expected_message="Please authorize charm (see `authorize-charm` action)",
        )
        unseal_all_vaults(unit_addresses, root_token, unseal_key)
        await helpers.wait_for_status_message(
            ops_test=ops_test,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            unit_name=f"{APPLICATION_NAME}/{leader_unit_index}",
        )
        await authorize_charm(ops_test, root_token)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    return leader_unit_index, root_token, unseal_key


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[int, str, str]:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    leader_unit_index = int(leader_unit.name.split("/")[-1])
    unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test, app_name)]
    client = hvac.Client(url=f"https://{unit_addresses[leader_unit_index]}:8200", verify=False)
    seal_type = client.seal_status["type"]  # type: ignore -- bad type hints in stubs
    if seal_type == "shamir":
        initialize_response = client.sys.initialize(secret_shares=1, secret_threshold=1)
        root_token, unseal_key = initialize_response["root_token"], initialize_response["keys"][0]
        try:
            await ops_test.model.add_secret(
                "initialization-secrets", [f"root-token={root_token}", f"unseal-key={unseal_key}"]
            )
        except JujuError:
            await ops_test.model.update_secret(
                "initialization-secrets",
                [f"root-token={root_token}", f"unseal-key={unseal_key}"],
                new_name="initialization-secrets",
            )
        return leader_unit_index, root_token, unseal_key
    initialize_response = client.sys.initialize(recovery_shares=1, recovery_threshold=1)
    root_token, recovery_key = (
        initialize_response["root_token"],
        initialize_response["recovery_keys"][0],
    )
    # Add the token/key to the model so they can be retrieved later if we need to debug
    await ops_test.model.add_secret(
        f"initialization-secrets-{app_name}",
        [f"root-token={root_token}", f"recovery-key={recovery_key}"],
    )
    return leader_unit_index, root_token, recovery_key


async def run_get_certificate_action(ops_test: OpsTest) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    assert isinstance(tls_requirer_unit, Unit)
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    assert isinstance(action, Action)
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def run_get_ca_certificate_action(ops_test: OpsTest, timeout: int = 60) -> dict:
    """Run the `get-certificate` on the `vault-k8s` unit.

    Args:
        ops_test (OpsTest): OpsTest
        timeout (int, optional): Timeout in seconds. Defaults to 60.

    Returns:
        dict: Action output
    """
    assert ops_test.model
    self_signed_certificates_unit = ops_test.model.units[
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0"
    ]
    assert isinstance(self_signed_certificates_unit, Unit)
    action = await self_signed_certificates_unit.run_action(
        action_name="get-ca-certificate",
    )
    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)


async def get_vault_ca_certificate(vault_unit: Unit) -> str:
    action = await vault_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
    await action.wait()
    return action.results["stdout"]


async def run_s3_integrator_sync_credentials_action(
    ops_test: OpsTest, access_key: str, secret_key: str
) -> dict:
    """Run the `sync-s3-credentials` action on the `s3-integrator` leader unit.

    Args:
        ops_test (OpsTest): OpsTest
        access_key (str): Access key of the S3 compatible storage
        secret_key (str): Secret key of the S3 compatible storage

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
    sync_credentials_action = await leader_unit.run_action(
        action_name="sync-s3-credentials",
        **{
            "access-key": access_key,
            "secret-key": secret_key,
        },
    )
    return await ops_test.model.get_action_output(
        action_uuid=sync_credentials_action.entity_id, wait=120
    )


async def run_create_backup_action(ops_test: OpsTest) -> dict:
    """Run the `create-backup` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    create_backup_action = await leader_unit.run_action(
        action_name="create-backup",
    )
    return await ops_test.model.get_action_output(
        action_uuid=create_backup_action.entity_id, wait=120
    )


async def run_list_backups_action(ops_test: OpsTest) -> dict:
    """Run the `list-backups` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    list_backups_action = await leader_unit.run_action(
        action_name="list-backups",
    )
    return await ops_test.model.get_action_output(
        action_uuid=list_backups_action.entity_id, wait=120
    )


async def run_restore_backup_action(ops_test: OpsTest, backup_id: str) -> dict:
    """Run the `restore-backup` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest
        backup_id (str): Backup ID
        root_token (str): Root token of the Vault
        unseal_keys (List[str]): Unseal keys of the Vault

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    restore_backup_action = await leader_unit.run_action(
        action_name="restore-backup",
        **{"backup-id": backup_id},
    )
    await restore_backup_action.wait()
    return restore_backup_action.results


async def read_vault_unit_statuses(
    ops_test: OpsTest, app_name: str = APPLICATION_NAME
) -> List[Dict[str, str]]:
    """Read the complete status from vault units.

    Reads the statuses that juju emits that aren't captured by ops_test together. Captures a vault
    units: name, status (active, blocked etc.), agent (idle, executing), address and message.

    Args:
        ops_test: Ops test Framework
        app_name: Application name of the Vault, defaults to "vault-k8s"
    """
    status_tuple = await ops_test.juju("status")
    if status_tuple[0] != 0:
        raise Exception
    output = []
    for row in status_tuple[1].split("\n"):
        if not row.startswith(f"{app_name}/"):
            continue
        cells = row.split(maxsplit=4)
        if len(cells) < 5:
            cells.append("")
        output.append(
            {
                "unit": cells[0],
                "status": cells[1],
                "agent": cells[2],
                "address": cells[3],
                "message": cells[4],
            }
        )
    return output


def unseal_vault(endpoint: str, root_token: str, unseal_key: str):
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    if not client.sys.is_sealed():
        return
    client.sys.submit_unseal_key(unseal_key)


def unseal_all_vaults(unit_addresses: List[str], root_token: str, unseal_key: str):
    for endpoint in unit_addresses:
        unseal_vault(endpoint, root_token, unseal_key)


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str = APPLICATION_NAME, attempts: int = 3
) -> Any | Dict:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    try:
        secret = await ops_test.model.add_secret(
            f"approle-token-{app_name}", [f"token={root_token}"]
        )
    except JujuError:
        await ops_test.model.update_secret(
            f"approle-token-{app_name}",
            [f"token={root_token}"],
            new_name=f"approle-token-{app_name}",
        )
        secret = await helpers.get_model_secret_id(ops_test, f"approle-token-{app_name}")
    secret_id = secret.split(":")[-1]
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)
    for _ in range(attempts):
        authorize_action = await leader_unit.run_action(
            action_name="authorize-charm",
            **{
                "secret-id": secret_id,
            },
        )
        result = await ops_test.model.get_action_output(
            action_uuid=authorize_action.entity_id, wait=120
        )
        if result and "result" in result:
            return result
        await asyncio.sleep(5)
    raise ActionFailedError("Failed to authorize charm")
