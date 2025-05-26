#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
import time
from base64 import b64decode
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import hvac
import requests
import yaml
from cryptography import x509
from juju.application import Application
from juju.errors import JujuError
from juju.model import Model
from juju.unit import Unit
from lightkube.core.client import Client as KubernetesClient
from lightkube.resources.core_v1 import Pod
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    VAULT_RESOURCES,
)
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


def retry(
    exceptions: tuple | None = None,
    attempts: int = 3,
    wait_time: timedelta | float | None = None,
):
    """Retry decorator.

    Args:
        exceptions: Exceptions to retry on.
        attempts: Number of attempts to retry.
        wait_time: Time to wait between attempts.
    """
    wait_time_s = (
        wait_time.total_seconds()
        if isinstance(wait_time, timedelta)
        else wait_time
        if wait_time
        else 0
    )

    def decorator(func: Callable):
        async def wrapper(*args: Any, **kwargs: Any):
            for attempt in range(attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if exceptions and not isinstance(e, exceptions):
                        logger.info(
                            "Not retrying, exception type %s not in %s", type(e), exceptions
                        )
                        raise e
                    if attempt == attempts - 1:
                        import pdb

                        pdb.set_trace()
                        raise e
                    if wait_time:
                        logger.info("Retrying in %s seconds...", wait_time_s)
                        await asyncio.sleep(wait_time_s)

        return wrapper

    return decorator


def crash_pod(name: str, namespace: str) -> None:
    """Simulate a pod crash by deleting the pod."""
    k8s = KubernetesClient()
    k8s.delete(Pod, name=name, namespace=namespace)


async def get_leader_unit(model: Model, application_name: str) -> Unit:
    """Return the leader unit for the given application."""
    for unit in model.units.values():
        assert unit
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


async def get_unit_status_messages(
    ops_test: OpsTest, app_name: str = APPLICATION_NAME
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


def get_first(d: dict) -> Any:
    return next(iter(d.values()))


async def get_unit_address(ops_test: OpsTest, unit_name: str) -> str:
    """Get the address of a unit."""
    return_code, stdout, stderr = await ops_test.juju("status", "--format", "yaml", unit_name)
    if return_code:
        raise RuntimeError(stderr)
    output = yaml.safe_load(stdout)
    unit_status = get_first(get_first(output["applications"])["units"])
    return unit_status["address"]


async def wait_for_status_message(
    ops_test: OpsTest,
    expected_message: str,
    app_name: str = APPLICATION_NAME,
    count: int = 1,
    timeout: int = 100,
    cadence: int = 2,
    unit_name: str | None = None,
) -> None:
    """Wait for the correct status messages to appear.

    Args:
        ops_test: Ops test Framework.
        app_name: Application name of the Vault, defaults to "vault-k8s"
        count: How many units are expected to be emitting the message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time, in seconds, before giving up
        cadence: How often to check the status of the units
        unit_name: The name of the unit to check the status of

    Raises:
        TimeoutError: If the expected amount of statuses weren't found in the given timeout.
    """
    seen = 0
    unit_statuses = []
    if unit_name and count > 1:
        raise ValueError("Cannot specify unit name and count > 1")
    while timeout > 0:
        unit_statuses = await get_unit_status_messages(ops_test, app_name=app_name)
        seen = 0
        for current_unit_name, unit_status_message in unit_statuses:
            if unit_name:
                if current_unit_name == unit_name:
                    if unit_status_message == expected_message:
                        return
            elif unit_status_message == expected_message:
                seen += 1

        if seen == count:
            return
        time.sleep(cadence)
        timeout -= cadence

    raise TimeoutError(
        f"`{app_name}` didn't show the expected status: `{expected_message}`. Last statuses: {unit_statuses}"
    )


async def get_vault_client(
    ops_test: OpsTest, unit_name: str, token: str, ca_file_name: str | None = None
) -> Vault:
    """Get a Vault client for the given application."""
    address = await get_unit_address(ops_test, unit_name)
    return Vault(url=f"https://{address}:8200", token=token, ca_file_location=ca_file_name)


async def get_model_secret_field(ops_test: OpsTest, label: str, field: str) -> str:
    secrets = await ops_test.model.list_secrets(show_secrets=True)  # type: ignore
    secret = next(secret for secret in secrets if secret.label == label)
    field_content = b64decode(secret.value.data[field]).decode("utf-8")
    return field_content


async def get_model_secret_id(ops_test: OpsTest, label: str) -> str:
    secrets = await ops_test.model.list_secrets(show_secrets=True)  # type: ignore
    secret = next(secret for secret in secrets if secret.label == label)
    return secret.uri


def get_vault_pki_intermediate_ca_common_name(root_token: str, endpoint: str, mount: str) -> str:
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    ca_cert = client.secrets.pki.read_ca_certificate(mount_point=mount)
    assert ca_cert, "No CA certificate found"
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )


def revoke_token(token_to_revoke: str, root_token: str, endpoint: str):
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    client.revoke_token(token=token_to_revoke)


async def get_leader(app: Application) -> Unit:
    for unit in app.units:
        assert isinstance(unit, Unit)
        if await unit.is_leader_from_status():
            return unit
    raise Exception("Leader unit not found.")


async def get_vault_token_and_unseal_key(
    model: Model, app_name: str = APPLICATION_NAME
) -> Tuple[str, str]:
    root_token, unseal_key = await get_juju_secret(
        model, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, unseal_key


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    assert ops_test.model

    leader = await get_leader(ops_test.model.applications[app_name])
    address = await get_unit_address(ops_test, leader.name)

    vault_url = f"https://{address}:8200"

    vault = Vault(
        url=vault_url, ca_file_location=await get_ca_cert_file_location(ops_test, app_name)
    )
    if not await is_initialized(vault):
        root_token, key = vault.initialize()
        await ops_test.model.add_secret(
            f"root-token-key-{app_name}", [f"root-token={root_token}", f"key={key}"]
        )
        logger.info("Vault initialized")
        return root_token, key

    root_token, key = await get_vault_token_and_unseal_key(ops_test.model, app_name=app_name)
    logger.info("Vault is already initialized")
    return root_token, key


@retry(
    exceptions=(requests.exceptions.ConnectionError,),
    wait_time=5,
    attempts=5,
)
async def is_initialized(vault: Vault) -> bool:
    """Check if the vault unit is initialized."""
    # TODO: add note about why we are retrying on ConnectionError here
    return vault.is_initialized()


async def unseal_all_vault_units_and_wait(
    ops_test: OpsTest, unseal_key: str, token: str, ca_file_name: str | None = None
) -> None:
    """Unseal all the vault units and wait for them to be unsealed."""
    assert ops_test.model
    logger.info("Unsealing all vault units...")

    await unseal_all_vault_units(ops_test, unseal_key, token, ca_file_name)
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    logger.info("All vault units unsealed.")


async def authorize_charm_and_wait(
    ops_test: OpsTest, root_token: str, app_name: str = APPLICATION_NAME
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


async def unseal_all_vault_units(
    ops_test: OpsTest, unseal_key: str, token: str, ca_file_name: str | None = None
) -> None:
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[APPLICATION_NAME]
    assert isinstance(app, Application)

    # We need to unseal the leader first, since this is the one we initialized.
    leader = await get_leader(app)
    assert isinstance(leader, Unit)
    vault = await get_vault_client(ops_test, leader.name, unseal_key, ca_file_name)
    if vault.is_sealed():
        vault.unseal(unseal_key)
    await vault.wait_for_node_to_be_unsealed()

    for unit in app.units:
        assert isinstance(unit, Unit)
        vault = await get_vault_client(ops_test, unit.name, token, ca_file_name)
        await unseal_vault_unit(vault, unseal_key)
        await vault.wait_for_node_to_be_unsealed()


async def unseal_vault_unit(vault: Vault, unseal_key: str) -> None:
    """Unseal a vault, handle cases where it is temporarily unreachable.

    Args:
        vault: The Vault instance to unseal
        unseal_key: The unseal key for the vault
    """
    # TODO: replace with retry decorator
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


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str = APPLICATION_NAME, attempts: int = 12
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
        secret = await get_model_secret_id(ops_test, f"approle-token-{app_name}")
    secret_id = secret.split(":")[-1]
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)
    for attempt in range(1, attempts + 1):
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
        logger.warning(
            "Failed to authorize charm. Attempt %d/%d. Waiting for 5 seconds...",
            attempt,
            attempts,
        )
        await asyncio.sleep(5)
    logging.error("Failed to authorize charm with secret id %s", secret_id)
    raise ActionFailedError("Failed to authorize charm")


async def deploy_if_not_exists(
    model: Model,
    app_name: str,
    charm_path: Path | None = None,
    num_units: int = 1,
    config: dict | None = None,
    channel: str | None = None,
    revision: int | None = None,
    series: str | None = None,
    resources: Dict[str, str] | None = None,
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
                resources=resources,
            )
        except JujuError as e:
            logger.warning("Failed to deploy the `%s` charm: `%s`", app_name, e)


async def get_juju_secret(model: Model, label: str, fields: List[str]) -> List[str]:
    secrets = await model.list_secrets(show_secrets=True)
    secret = next(secret for secret in secrets if secret.label == label)

    return [b64decode(secret.value.data[field]).decode("utf-8") for field in fields]


async def deploy_vault(ops_test: OpsTest, charm_path: Path, num_units: int) -> None:
    """Ensure the Vault charm is deployed."""
    assert ops_test.model
    await deploy_if_not_exists(
        ops_test.model,
        APPLICATION_NAME,
        charm_path,
        num_units=num_units,
        resources=VAULT_RESOURCES,
    )


async def deploy_vault_and_wait(
    ops_test: OpsTest,
    charm_path: Path,
    num_units: int,
    status: str | None = None,
) -> None:
    await deploy_vault(ops_test, charm_path, num_units)
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            wait_for_at_least_units=num_units,
            timeout=1000,
            status=status,
        )
        logger.info("Vault deployed and idle.")


async def get_ca_cert_file_location(
    ops_test: OpsTest, app_name: str = APPLICATION_NAME
) -> str | None:
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


def get_app(model: Model, app_name: str = APPLICATION_NAME) -> Application:
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


async def initialize_unseal_authorize_vault(ops_test: OpsTest, app_name: str) -> tuple[str, str]:
    assert ops_test.model
    root_token, unseal_key = await initialize_vault_leader(ops_test, app_name)
    leader = await get_leader_unit(ops_test.model, app_name)
    leader_unit_address = await get_unit_address(ops_test, leader.name)

    vault_url = f"https://{leader_unit_address}:8200"
    vault = Vault(url=vault_url, token=root_token)
    assert vault.is_sealed()

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key, root_token)
        await authorize_charm_and_wait(ops_test, root_token)
    return root_token, unseal_key


async def get_vault_ca_certificate(vault_unit: Unit) -> str:
    action = await vault_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
    await action.wait()
    return action.results["stdout"]
