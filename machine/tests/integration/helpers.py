#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time
from base64 import b64decode
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests
import yaml
from cryptography import x509
from juju.application import Application
from juju.errors import JujuError
from juju.model import Model
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
)
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


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
        raise ActionFailedError(f"Failed to authorize charm. Result: {result}")
    logger.info("Authorization result: %s", result)
    return result


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


def has_relation(app: Application, relation_name: str) -> bool:
    """Check if the application has the relation with the given name.

    This is a hack since `app.related_applications` does not seem to work.
    """
    for relation in app.relations:
        for endpoint in relation.endpoints:
            if endpoint.application_name != app.name:
                continue
            if endpoint.name == relation_name:
                return True
    return False


async def get_ca_cert_file_location(ops_test: OpsTest, app_name: str = APP_NAME) -> str | None:
    """Get the location of the CA certificate file."""
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    if not has_relation(app, "tls-certificates-access"):
        return None
    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    assert ca_certificate
    ca_file_location = str(ops_test.tmp_path / f"ca_file_{app_name}.txt")
    with open(ca_file_location, mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    return ca_file_location


async def run_get_ca_certificate_action(ops_test: OpsTest, timeout: int = 60) -> dict:
    """Run the `get-certificate` on the `self-signed-certificates` unit.

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
    action = await self_signed_certificates_unit.run_action(
        action_name="get-ca-certificate",
    )
    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)


async def get_leader(app: Application) -> Unit:
    for unit in app.units:
        if await unit.is_leader_from_status():
            return unit
    raise Exception("Leader unit not found.")


async def unseal_all_vault_units(
    ops_test: OpsTest, ca_file_name: str | None, unseal_key: str
) -> None:
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]

    # We need to unseal the leader first, since this is the one we initialized.
    leader = await get_leader(app)
    unit_address = leader.public_address
    assert unit_address
    vault = Vault(url=f"https://{unit_address}:8200")
    if vault.is_sealed():
        vault.unseal(unseal_key)
    await vault.wait_for_node_to_be_unsealed()

    for unit in app.units:
        unit_address = unit.public_address
        assert unit_address
        vault = Vault(url=f"https://{unit_address}:8200", ca_file_location=ca_file_name)
        await unseal_vault_unit(vault, unseal_key)
        await vault.wait_for_node_to_be_unsealed()


async def unseal_vault_unit(vault: Vault, unseal_key: str) -> None:
    """Unseal a vault, handle cases where it is temporarily unreachable.

    Args:
        vault: The Vault instance to unseal
        unseal_key: The unseal key for the vault
    """
    count = 0
    while count < 10:
        count += 1
        try:
            if not vault.is_sealed():
                return
            vault.unseal(unseal_key)
            return
        except requests.exceptions.ConnectionError:
            logger.warning("Failed to connect to vault unit %s. Waiting...", vault.url)
            await asyncio.sleep(5)
    raise Exception("Timed out waiting for vault unit to be reachable.")


async def run_get_certificate_action(ops_test: OpsTest) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=30)
    return action_output


async def wait_for_certificate_to_be_provided(ops_test: OpsTest) -> None:
    start_time = time.time()
    timeout = 300
    while time.time() - start_time < timeout:
        action_output = await run_get_certificate_action(ops_test)
        if action_output.get("certificate", None) is not None:
            return
        await asyncio.sleep(10)
    raise TimeoutError("Timed out waiting for certificate to be provided.")


async def get_leader_unit(model: Model, application_name: str) -> Unit:
    """Return the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


async def get_unit_status_messages(
    ops_test: OpsTest, app_name: str = APP_NAME
) -> List[tuple[str, str]]:
    """Get the status messages from all the units of the given application.

    Returns:
        A list of tuples with the unit name in the first entry, and the status
        message in the second
    """
    # TODO: Can we use ops_test.model.get_status() instead?
    return_code, stdout, stderr = await ops_test.juju("status", "--format", "yaml", app_name)
    if return_code:
        raise RuntimeError(stderr)
    output = yaml.safe_load(stdout)
    unit_statuses = output["applications"][app_name]["units"]
    return [
        (unit_name, unit_status["workload-status"].get("message", ""))
        for (unit_name, unit_status) in unit_statuses.items()
    ]


async def wait_for_status_message(
    ops_test: OpsTest,
    expected_message: str,
    app_name: str = APP_NAME,
    count: int = 1,
    timeout: int = 100,
    cadence: int = 2,
) -> None:
    """Wait for the correct status messages to appear.

    Args:
        ops_test: Ops test Framework.
        app_name: Application name of the Vault, defaults to "vault-k8s"
        count: How many units are expected to be emitting the message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time, in seconds, before giving up
        cadence: How often to check the status of the units

    Raises:
        TimeoutError: If the expected amount of statuses weren't found in the given timeout.
    """
    seen = 0
    unit_statuses = []
    while timeout > 0:
        unit_statuses = await get_unit_status_messages(ops_test, app_name=app_name)
        seen = 0
        for unit_name, unit_status_message in unit_statuses:
            if unit_status_message == expected_message:
                seen += 1

        if seen == count:
            return
        await asyncio.sleep(cadence)
        timeout -= cadence

    raise TimeoutError(
        f"`{app_name}` didn't show the expected status: `{expected_message}`. Last statuses: {unit_statuses}"
    )


async def deploy_vault(ops_test: OpsTest, charm_path: Path, num_vaults: int) -> None:
    """Ensure the Vault charm is deployed."""
    assert ops_test.model
    await deploy_if_not_exists(ops_test.model, APP_NAME, charm_path, num_units=num_vaults)


async def deploy_vault_and_wait(
    ops_test: OpsTest, charm_path: Path, num_units: int, status: str | None = None
) -> None:
    await deploy_vault(ops_test, charm_path, num_units)
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            wait_for_at_least_units=num_units,
            timeout=1000,
            status=status,
        )


async def get_leader_unit_address(ops_test: OpsTest) -> str:
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    leader = await get_leader(app)
    assert leader and leader.public_address
    return leader.public_address


async def deploy_if_not_exists(
    model: Model,
    app_name: str,
    charm_path: Path | None = None,
    num_units: int = 1,
    config: dict | None = None,
    channel: str | None = None,
    revision: int | None = None,
    series: str | None = None,
) -> None:
    if app_name not in model.applications:
        try:
            await model.deploy(
                charm_path if charm_path else app_name,
                application_name=app_name,
                num_units=num_units,
                config=config,
                channel=channel,
                revision=revision,
                series=series,
            )
        except JujuError as e:
            logger.warning("Failed to deploy the `%s` charm: `%s`", app_name, e)


async def get_juju_secret(model: Model, label: str, fields: List[str]) -> List[str]:
    secrets = await model.list_secrets(show_secrets=True)
    secret = next(secret for secret in secrets if secret.label == label)

    return [b64decode(secret.value.data[field]).decode("utf-8") for field in fields]


def get_vault_pki_intermediate_ca_common_name(
    root_token: str, unit_address: str, mount: str
) -> str:
    vault = Vault(
        url=f"https://{unit_address}:8200",
        token=root_token,
    )
    ca_cert: str = vault.client.secrets.pki.read_ca_certificate(mount_point=mount)
    assert ca_cert, "No CA certificate found"
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    )
