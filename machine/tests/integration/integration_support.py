#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from asyncio import Task, create_task
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest
import yaml
from cryptography import x509
from juju.application import Application
from pytest_operator.plugin import OpsTest
from vault import Vault  # type: ignore[import]

from tests.integration.helpers import (
    deploy_if_not_exists,
    deploy_vault_and_wait,
    get_ca_cert_file_location,
    get_juju_secret,
    get_leader,
    get_leader_unit,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
GRAFANA_AGENT_SERIES = "jammy"
GRAFANA_AGENT_CHANNEL = "1/stable"
PEER_RELATION_NAME = "vault-peers"
INGRESS_RELATION_NAME = "ingress"
HAPROXY_APPLICATION_NAME = "haproxy"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_REVISION = 263
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
NUM_VAULT_UNITS = 3
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MATCHING_COMMON_NAME = "example.com"
UNMATCHING_COMMON_NAME = "unmatching-the-requirer.com"
VAULT_PKI_REQUIRER_REVISION = 93
CURRENT_TRACK_FIRST_STABLE_REVISION = 387
CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.16/stable"


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


@pytest.fixture(scope="session")
def vault_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--charm_path"))).resolve()


@pytest.fixture(scope="session")
def kv_requirer_charm_path(request: pytest.FixtureRequest) -> Path:
    path = request.config.getoption("--kv_requirer_charm_path")
    if not isinstance(path, str) or not path:
        pytest.fail("--kv_requirer_charm_path is required for KV integration tests")
    return Path(path).resolve()


@pytest.fixture(scope="function")
async def vault_idle(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be blocked.

    This is the default state of Vault.
    """
    return create_task(
        deploy_vault_and_wait(
            ops_test=ops_test, num_units=NUM_VAULT_UNITS, charm_path=vault_charm_path
        )
    )


@pytest.fixture(scope="function")
async def vault_idle_blocked(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be blocked.

    This is the default state of Vault.
    """
    return create_task(
        deploy_vault_and_wait(
            ops_test=ops_test,
            num_units=NUM_VAULT_UNITS,
            charm_path=vault_charm_path,
            status="blocked",
        )
    )


@pytest.fixture(scope="function")
async def vault_initialized(ops_test: OpsTest, vault_idle: Task) -> Task:
    async def deploy_and_initialize():
        assert ops_test.model

        await vault_idle
        return await initialize_vault_leader(ops_test, APP_NAME)

    return create_task(deploy_and_initialize())


@pytest.fixture(scope="function")
async def vault_unsealed(ops_test: OpsTest, vault_initialized: Task) -> Task:
    assert ops_test.model
    root_token, unseal_key = await vault_initialized

    async def task():
        await unseal_all_vault_units(
            ops_test, await get_ca_cert_file_location(ops_test), unseal_key
        )
        return root_token, unseal_key

    return create_task(task())


@pytest.fixture(scope="function")
async def vault_authorized(ops_test: OpsTest, vault_unsealed: Task) -> Task:
    assert ops_test.model
    root_token, key = await vault_unsealed

    async def authorize():
        try:
            await authorize_charm(ops_test, root_token)
        except ActionFailedError:
            logger.warning("Failed to authorize charm")
        return root_token, key

    return create_task(authorize())


@pytest.fixture(scope="module")
async def self_signed_certificates_idle(ops_test: OpsTest) -> Task:
    """Deploy the `self-signed-certificates` charm."""

    async def deploy_self_signed_certificates(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model,
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            channel="1/stable",
            revision=SELF_SIGNED_CERTIFICATES_REVISION,
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            )

    return create_task(deploy_self_signed_certificates(ops_test))


@pytest.fixture(scope="module")
async def haproxy_idle(ops_test: OpsTest) -> Task:
    """Deploy the `haproxy` charm."""

    async def deploy_haproxy(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(ops_test.model, HAPROXY_APPLICATION_NAME, channel="2.8/edge")
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[HAPROXY_APPLICATION_NAME],
            )

    return create_task(deploy_haproxy(ops_test))


@pytest.fixture(scope="module")
async def vault_kv_requirer_idle(ops_test: OpsTest, kv_requirer_charm_path: Path) -> Task:
    """Deploy the `vault-kv-requirer` charm."""

    async def deploy_kv_requirer(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model, VAULT_KV_REQUIRER_APPLICATION_NAME, charm_path=kv_requirer_charm_path
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[VAULT_KV_REQUIRER_APPLICATION_NAME],
            )

    return create_task(deploy_kv_requirer(ops_test))


@pytest.fixture(scope="module")
async def vault_pki_requirer_idle(ops_test: OpsTest) -> Task:
    """Deploy the `vault-pki-requirer` charm."""

    async def deploy_pki_requirer(ops_test: OpsTest):
        assert ops_test.model
        config = {
            "common_name": f"test.{MATCHING_COMMON_NAME}",
            "sans_dns": f"test.{MATCHING_COMMON_NAME}",
        }
        await deploy_if_not_exists(
            ops_test.model,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
            config=config,
            revision=VAULT_PKI_REQUIRER_REVISION,
            channel="stable",
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
        )

    return create_task(deploy_pki_requirer(ops_test))


@pytest.fixture(scope="module")
async def grafana_deployed(ops_test: OpsTest) -> Task:
    """Deploy the `grafana-agent` charm."""
    assert ops_test.model

    return create_task(
        deploy_if_not_exists(
            ops_test.model,
            GRAFANA_AGENT_APPLICATION_NAME,
            channel=GRAFANA_AGENT_CHANNEL,
            series=GRAFANA_AGENT_SERIES,
        )
    )


@pytest.fixture(scope="module")
async def s3_integrator_idle(ops_test: OpsTest) -> Task:
    """Deploy the `s3-integrator` charm."""

    async def deploy_s3_integrator(ops_test: OpsTest):
        assert ops_test.model

        await deploy_if_not_exists(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
        )

    return create_task(deploy_s3_integrator(ops_test))


def get_vault_pki_intermediate_ca_common_name(
    root_token: str, unit_address: str, mount: str
) -> str:
    vault = Vault(
        url=f"https://{unit_address}:8200",
        token=root_token,
    )
    ca_cert = vault.client.secrets.pki.read_ca_certificate(mount_point=mount)
    assert ca_cert, "No CA certificate found"
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )


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
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
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
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
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
        backup_id (str): Backup ID to restore
    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
    restore_backup_action = await leader_unit.run_action(
        action_name="restore-backup",
        **{"backup-id": backup_id},
    )
    return await ops_test.model.get_action_output(
        action_uuid=restore_backup_action.entity_id, wait=120
    )


async def get_leader_vault_client(ops_test: OpsTest, app_name: str) -> Vault:
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    vault_url = f"https://{leader_ip}:8200"
    ca_file_location = get_ca_cert_file_location(ops_test)
    return Vault(url=vault_url, ca_file_location=await ca_file_location)


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    vault_url = f"https://{leader_ip}:8200"

    vault = Vault(
        url=vault_url, ca_file_location=await get_ca_cert_file_location(ops_test, app_name)
    )
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        await ops_test.model.add_secret(
            f"root-token-key-{app_name}", [f"root-token={root_token}", f"key={key}"]
        )
        return root_token, key

    root_token, key = await get_juju_secret(
        ops_test.model, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, key


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str = APP_NAME
) -> Any | Dict:
    """Authorize the charm to interact with Vault.

    Returns:
        Action output
    """
    assert ops_test.model

    assert isinstance(app := ops_test.model.applications[app_name], Application)
    if app.status == "active":
        logger.info("The charm is already active, skipping authorization.")
        return
    logger.info("Authorizing the charm `%s` to interact with Vault.", app_name)
    secret = await ops_test.model.add_secret(f"approle-token-{app_name}", [f"token={root_token}"])
    secret_id = secret.split(":")[-1]
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    authorize_action = await leader_unit.run_action(
        action_name="authorize-charm",
        **{
            "secret-id": secret_id,
        },
    )
    result = await ops_test.model.get_action_output(
        action_uuid=authorize_action.entity_id, wait=120
    )
    if not result or "result" not in result:
        raise ActionFailedError("Failed to authorize charm")
    logger.info("Authorization result: %s", result)
    return result
