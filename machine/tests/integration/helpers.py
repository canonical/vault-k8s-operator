#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from base64 import b64decode
from pathlib import Path
from typing import List

import yaml
from juju.application import Application
from juju.errors import JujuError
from juju.model import Model
from juju.unit import Unit
from pytest_operator.plugin import OpsTest
from vault import Vault  # type: ignore[import]

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"

logger = logging.getLogger(__name__)


def get_app(model: Model, app_name: str = APP_NAME) -> Application:
    """Get the application by name.

    Abstracts some of the boilerplate code needed to get the application caused
    by the type stubs in pytest_operator being non-committal.
    """
    app = model.applications[app_name]
    assert isinstance(app, Application)
    return app


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
    app = get_app(ops_test.model, app_name)
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
    assert isinstance(self_signed_certificates_unit, Unit)
    action = await self_signed_certificates_unit.run_action(
        action_name="get-ca-certificate",
    )
    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)


async def get_leader(app: Application) -> Unit:
    for unit in app.units:
        assert isinstance(unit, Unit)
        if await unit.is_leader_from_status():
            return unit
    raise Exception("Leader unit not found.")


async def unseal_all_vault_units(
    ops_test: OpsTest, ca_file_name: str | None, unseal_key: str
) -> None:
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)

    # We need to unseal the leader first, since this is the one we initialized.
    leader = await get_leader(app)
    assert isinstance(leader, Unit)
    unit_address = leader.public_address
    assert unit_address
    vault = Vault(url=f"https://{unit_address}:8200")
    if vault.is_sealed():
        vault.unseal(unseal_key)
    vault.wait_for_node_to_be_unsealed()

    for unit in app.units:
        assert isinstance(unit, Unit)
        unit_address = unit.public_address
        assert unit_address
        vault = Vault(url=f"https://{unit_address}:8200", ca_file_location=ca_file_name)
        if vault.is_sealed():
            vault.unseal(unseal_key)
        vault.wait_for_node_to_be_unsealed()


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
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=30)
    return action_output


async def wait_for_certificate_to_be_provided(ops_test: OpsTest) -> None:
    start_time = time.time()
    timeout = 300
    while time.time() - start_time < timeout:
        action_output = await run_get_certificate_action(ops_test)
        if action_output.get("certificate", None) is not None:
            return
        time.sleep(10)
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
        time.sleep(cadence)
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
    async with ops_test.fast_forward(fast_interval="60s"):
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
    assert isinstance(app, Application)
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
    base: str | None = None,
    revision: int | None = None,
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
                base=base,
            )
        except JujuError as e:
            logger.warning("Failed to deploy the `%s` charm: `%s`", app_name, e)


async def get_juju_secret(model: Model, label: str, fields: List[str]) -> List[str]:
    secrets = await model.list_secrets(show_secrets=True)
    secret = next(secret for secret in secrets if secret.label == label)

    return [b64decode(secret.value.data[field]).decode("utf-8") for field in fields]
