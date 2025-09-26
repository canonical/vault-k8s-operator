#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time
from base64 import b64decode
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
from cryptography import x509
from juju.action import Action
from juju.application import Application
from juju.errors import JujuError
from juju.model import Model
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
)
from vault_helpers import Vault

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

    return await run_action_on_leader(
        ops_test,
        app_name,
        action_name="authorize-charm",
        secret_id=secret_id,
    )


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    vault = await get_vault_client(ops_test, leader)
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        await ops_test.model.add_secret(
            f"root-token-key-{app_name}", [f"root-token={root_token}", f"key={key}"]
        )
        return root_token, key

    root_token, key = await get_vault_token_and_unseal_key(ops_test.model, app_name)
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


async def authorize_charm_and_wait(
    ops_test: OpsTest, root_token: str, app_name: str = APP_NAME
) -> Any | Dict:
    """Authorize the charm and wait for it to be authorized.

    Args:
        ops_test: Ops test Framework
        root_token: The root token for the vault
        app_name: Application name of the Vault, defaults to "vault-k8s"

    Returns:
        Any | Dict: The result of the authorization
    """
    assert ops_test.model
    result = await authorize_charm(ops_test, root_token, app_name)
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[app_name],
            status="active",
            timeout=60,  # Since we're not raising on error, don't wait too long. This should be quick.
            wait_for_at_least_units=1,
            raise_on_error=False,  # Sometimes the charm reports an InternalServerError immediately after authorization, but it resolves itself.
        )
    logger.info("Charm authorized")
    return result


async def get_vault_token_and_unseal_key(
    model: Model, app_name: str = APP_NAME
) -> Tuple[str, str]:
    root_token, unseal_key = await get_juju_secret(
        model, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, unseal_key


async def initialize_unseal_authorize_vault(ops_test: OpsTest, app_name: str) -> tuple[str, str]:
    assert ops_test.model
    root_token, unseal_key = await initialize_vault_leader(ops_test, app_name)
    leader = await get_leader_unit(ops_test.model, app_name)
    vault = await get_vault_client(ops_test, leader, root_token)
    assert vault.is_sealed()

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key)
        await authorize_charm_and_wait(ops_test, root_token)
    return root_token, unseal_key


async def get_vault_client(
    ops_test: OpsTest, unit: Unit, token: str | None = None, ca_file_name: str | None = None
) -> Vault:
    """Get a Vault client for the given application."""
    return Vault(
        url=f"https://{unit.public_address}:8200", token=token, ca_file_location=ca_file_name
    )


def get_first(d: dict) -> Any:
    return next(iter(d.values()))


async def get_leader(app: Application) -> Unit:
    for unit in app.units:
        if await unit.is_leader_from_status():
            return unit
    raise Exception("Leader unit not found.")


async def unseal_all_vault_units(
    ops_test: OpsTest, unseal_key: str, ca_file_name: str | None = None
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
        vault.unseal(unseal_key)
        await vault.wait_for_node_to_be_unsealed()


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


async def deploy_vault(
    ops_test: OpsTest,
    num_vaults: int,
    channel: str | None = None,
    charm_path: Path | None = None,
    revision: int | None = None,
) -> None:
    """Ensure the Vault charm is deployed."""
    assert ops_test.model
    await deploy_if_not_exists(
        ops_test.model,
        app_name=APP_NAME,
        charm_path=charm_path,
        num_units=num_vaults,
        channel=channel,
        revision=revision,
    )


async def deploy_vault_and_wait(
    ops_test: OpsTest,
    num_units: int,
    status: str | None = None,
    channel: str | None = None,
    charm_path: Path | None = None,
    revision: int | None = None,
) -> None:
    await deploy_vault(
        ops_test, num_vaults=num_units, channel=channel, charm_path=charm_path, revision=revision
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            wait_for_at_least_units=num_units,
            timeout=1000,
            status=status,
        )


async def get_leader_unit_address(model: Model, app_name: str = APP_NAME) -> str:
    app = model.applications[app_name]
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
    trust: bool = False,
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
                trust=trust,
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


async def run_action_on_leader(
    ops_test: OpsTest, app_name: str, action_name: str, raise_on_error: bool = True, **kwargs: Any
) -> dict:
    """Run an action on the leader unit of the given application.

    Wait for the action to complete and return the output. Also, checks the action status and raises an error if it failed unless `raise_on_error` is False.

    Args:
        ops_test: The OpsTest instance.
        app_name: The name of the application to run the action on.
        action_name: The name of the action to run.
        raise_on_error: Whether to raise an error if the action fails. Defaults to True.
        **kwargs: Additional keyword arguments to pass to the action.
            Underscores in the keys will be replaced with dashes to match
            action parameter names.

    Returns:
        dict: The output of the action.

    """
    assert ops_test.model
    # Replace underscores in kwargs with dashes to match action parameter names
    kwargs = {k.replace("_", "-"): v for k, v in kwargs.items()}
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    action = await leader_unit.run_action(action_name=action_name, **kwargs)
    action: Action = await ops_test.model.wait_for_action(action.entity_id)
    logger.info(
        "Action `%s` on unit `%s` completed with status `%s`. Message: `%s`, Results: %s",
        action_name,
        leader_unit.name,
        action.status,
        action.data.get("message", ""),
        action.results,
    )
    if raise_on_error and action.status != "completed":
        raise ActionFailedError(
            f"Action {action_name} failed with status `{action.status}`. Message: {action.data.get('message', '')}"
        )

    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=120)


async def refresh_application(ops_test: OpsTest, app_name: str, charm_path: Path) -> None:
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    await app.refresh(path=charm_path)
