#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import contextlib
import logging
import platform
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

import hvac
import jubilant
from cryptography import x509
from lightkube.core.client import Client as KubernetesClient
from lightkube.resources.core_v1 import Pod

from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    VAULT_RESOURCES,
)
from vault_helpers import Vault

logger = logging.getLogger(__name__)


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


def crash_pod(name: str, namespace: str) -> None:
    """Simulate a pod crash by deleting the pod."""
    k8s = KubernetesClient()
    k8s.delete(Pod, name=name, namespace=namespace)


def get_leader_unit_name(juju: jubilant.Juju, application_name: str) -> str:
    """Return the name of the leader unit for the given application."""
    status = juju.status()
    for unit_name, unit_status in status.apps[application_name].units.items():
        if unit_status.leader:
            return unit_name
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


def get_unit_status_messages(
    juju: jubilant.Juju, app_name: str = APPLICATION_NAME
) -> List[tuple[str, str]]:
    """Get the status messages from all the units of the given application.

    Returns:
        A list of tuples with the unit name in the first entry, and the status
        message in the second
    """
    status = juju.status()
    units = status.apps[app_name].units
    return [(unit_name, unit.workload_status.message) for unit_name, unit in units.items()]


def get_unit_address(juju: jubilant.Juju, unit_name: str) -> str:
    """Get the address of a unit."""
    app_name = unit_name.rsplit("/", 1)[0]
    status = juju.status()
    return status.apps[app_name].units[unit_name].address


def wait_for_status_message(
    juju: jubilant.Juju,
    expected_message: str,
    app_name: str = APPLICATION_NAME,
    count: int = 1,
    timeout: int = 100,
    cadence: int = 2,
    unit_name: str | None = None,
) -> None:
    """Wait for the correct status messages to appear.

    Args:
        juju: Jubilant Juju instance.
        app_name: Application name of the Vault, defaults to "vault-k8s"
        count: How many units are expected to be emitting the message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time, in seconds, before giving up
        cadence: How often to check the status of the units
        unit_name: The name of the unit to check the status of

    Raises:
        TimeoutError: If the expected amount of statuses weren't found in the given timeout.
    """
    if unit_name and count > 1:
        raise ValueError("Cannot specify unit name and count > 1")

    def ready(status: jubilant.Status) -> bool:
        if app_name not in status.apps:
            return False
        units = status.apps[app_name].units
        if unit_name:
            if unit_name not in units:
                return False
            return units[unit_name].workload_status.message == expected_message
        seen = sum(1 for u in units.values() if u.workload_status.message == expected_message)
        return seen == count

    juju.wait(ready, timeout=timeout, delay=cadence)


def get_vault_client(
    juju: jubilant.Juju, unit_name: str, token: str, ca_file_name: str | None = None
) -> Vault:
    """Get a Vault client for the given application."""
    address = get_unit_address(juju, unit_name)
    return Vault(url=f"https://{address}:8200", token=token, ca_file_location=ca_file_name)


def get_model_secret_field(juju: jubilant.Juju, label: str, field: str) -> str:
    secrets = juju.secrets()
    try:
        secret = next(s for s in secrets if s.label == label)
        revealed = juju.show_secret(secret.uri, reveal=True)
    except StopIteration:
        revealed = juju.show_secret(label, reveal=True)
    return revealed.content[field]


def get_model_secret_id(juju: jubilant.Juju, label: str) -> str:
    secrets = juju.secrets()
    try:
        secret = next(s for s in secrets if s.label == label)
        return str(secret.uri)
    except StopIteration:
        # Fallback: look up directly by label in case juju.secrets() listing is incomplete
        secret = juju.show_secret(label)
        return str(secret.uri)


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


def get_vault_token_and_unseal_key(
    juju: jubilant.Juju, app_name: str = APPLICATION_NAME
) -> Tuple[str, str]:
    root_token, unseal_key = get_juju_secret(
        juju, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, unseal_key


def initialize_vault_leader(juju: jubilant.Juju, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Also adds the root token and unseal key to the model secrets so they can be
    retrieved if tests are run multiple times with a single deploy
    (`--no-deploy) or for debugging in the case of a failure.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    leader_name = get_leader_unit_name(juju, app_name)
    address = get_unit_address(juju, leader_name)

    vault_url = f"https://{address}:8200"

    vault = Vault(url=vault_url, ca_file_location=get_ca_cert_file_location(juju, app_name))
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        juju.add_secret(f"root-token-key-{app_name}", {"root-token": root_token, "key": key})
        logger.info("Vault initialized")
        return root_token, key

    root_token, key = get_vault_token_and_unseal_key(juju, app_name=app_name)
    logger.info("Vault is already initialized")
    return root_token, key


def authorize_charm_and_wait(
    juju: jubilant.Juju, root_token: str, app_name: str = APPLICATION_NAME
) -> Any | Dict:
    """Authorize the charm and wait for it to be authorized.

    Args:
        juju: Jubilant Juju instance.
        root_token: The root token for the vault
        app_name: Application name of the Vault, defaults to "vault-k8s"

    Returns:
        Any | Dict: The result of the authorization
    """
    result = authorize_charm(juju, root_token, app_name)
    with fast_forward(juju):
        juju.wait(
            lambda s: jubilant.all_active(s, app_name),
            timeout=60,
        )
    logger.info("Charm authorized")
    return result


def unseal_all_vault_units(
    juju: jubilant.Juju, unseal_key: str, token: str, ca_file_name: str | None = None
) -> None:
    """Unseal all the vault units."""
    status = juju.status()
    units = status.apps[APPLICATION_NAME].units

    # Find the leader first, since this is the one we initialized.
    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    vault = get_vault_client(juju, leader_name, unseal_key, ca_file_name)
    if vault.is_sealed():
        vault.unseal(unseal_key)
    vault.wait_for_node_to_be_unsealed()

    for unit_name in units:
        vault = get_vault_client(juju, unit_name, token, ca_file_name)
        vault.unseal(unseal_key)
        vault.wait_for_node_to_be_unsealed()


def authorize_charm(
    juju: jubilant.Juju, root_token: str, app_name: str = APPLICATION_NAME, attempts: int = 12
) -> Any | Dict:
    try:
        secret_uri = juju.add_secret(f"approle-token-{app_name}", {"token": root_token})
    except jubilant.CLIError:
        try:
            secret_id_str = get_model_secret_id(juju, f"approle-token-{app_name}")
            juju.update_secret(secret_id_str, {"token": root_token})
            secret_uri = secret_id_str
        except StopIteration:
            secret_uri = juju.add_secret(f"approle-token-{app_name}", {"token": root_token})
    secret_id = str(secret_uri).split(":")[-1]
    juju.grant_secret(f"approle-token-{app_name}", app_name)
    for attempt in range(1, attempts + 1):
        try:
            task = juju.run(
                f"{app_name}/leader",
                "authorize-charm",
                {"secret-id": secret_id},
                wait=120,
            )
            if task.results and "result" in task.results:
                return task.results
        except (jubilant.TaskError, jubilant.CLIError) as e:
            logger.warning(
                "Failed to authorize charm. Attempt %d/%d: %s",
                attempt,
                attempts,
                e,
            )
        time.sleep(5)
    logger.error("Failed to authorize charm")
    raise ActionFailedError("Failed to authorize charm")


def _get_arch() -> str:
    """Return the Juju architecture name for the current machine."""
    arch_map = {"x86_64": "amd64", "aarch64": "arm64", "s390x": "s390x"}
    return arch_map.get(platform.machine(), "amd64")


def _get_arch_constraint() -> str:
    """Return arch constraint matching the current machine architecture."""
    return f"arch={_get_arch()}"


def deploy_if_not_exists(
    juju: jubilant.Juju,
    app_name: str,
    charm_path: Path | None = None,
    num_units: int = 1,
    config: dict | None = None,
    channel: str | None = None,
    revision: int | None = None,
    resources: Dict[str, str] | None = None,
    trust: bool = True,
    constraints: str | None = None,
) -> None:
    status = juju.status()
    if app_name in status.apps:
        return
    try:
        juju.deploy(
            charm_path if charm_path else app_name,
            app_name,
            config=config,
            channel=channel,
            revision=revision,
            resources=resources if charm_path else None,
            trust=trust,
            num_units=num_units,
            constraints={"arch": constraints.split("=")[1]} if constraints else None,
        )
    except jubilant.CLIError as e:
        if "already exists" in (e.stderr or ""):
            logger.warning("Application `%s` already exists, skipping deploy", app_name)
            return
        raise


def get_juju_secret(juju: jubilant.Juju, label: str, fields: List[str]) -> List[str]:
    """Get a Juju secret from the model and return the specified fields.

    Args:
        juju: Jubilant Juju instance.
        label (str): The label of the secret to get.
        fields (List[str]): The fields to return from the secret.
    """
    secrets = juju.secrets()
    try:
        secret = next(s for s in secrets if s.label == label)
        revealed = juju.show_secret(secret.uri, reveal=True)
    except StopIteration:
        # Fallback: look up directly by label in case juju.secrets() listing is incomplete
        revealed = juju.show_secret(label, reveal=True)
    return [revealed.content[field] for field in fields]


def deploy_vault(
    juju: jubilant.Juju,
    num_units: int,
    charm_path: Path | None = None,
    channel: str | None = None,
    revision: int | None = None,
) -> None:
    """Ensure the Vault charm is deployed."""
    deploy_if_not_exists(
        juju,
        app_name=APPLICATION_NAME,
        charm_path=charm_path,
        num_units=num_units,
        resources=VAULT_RESOURCES,
        channel=channel,
        revision=revision,
        constraints=_get_arch_constraint(),
    )


def has_relation(juju: jubilant.Juju, app_name: str, relation_name: str) -> bool:
    """Check if the application has the relation with the given name."""
    status = juju.status()
    if app_name not in status.apps:
        return False
    return relation_name in status.apps[app_name].relations


def get_ca_cert_file_location(juju: jubilant.Juju, app_name: str = APPLICATION_NAME) -> str | None:
    """Get the location of the CA certificate file."""
    if not has_relation(juju, app_name, "tls-certificates-access"):
        return None
    task = juju.run(
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0", "get-ca-certificate", wait=60
    )
    ca_certificate = task.results.get("ca-certificate")
    assert ca_certificate
    ca_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False)
    ca_file.write(ca_certificate)
    ca_file.close()
    return ca_file.name


def initialize_unseal_authorize_vault(juju: jubilant.Juju, app_name: str) -> tuple[str, str]:
    root_token, unseal_key = initialize_vault_leader(juju, app_name)
    leader_name = get_leader_unit_name(juju, app_name)
    vault = get_vault_client(juju, leader_name, root_token)
    assert vault.is_sealed()

    with fast_forward(juju):
        unseal_all_vault_units(juju, unseal_key, root_token)
        authorize_charm_and_wait(juju, root_token)
    return root_token, unseal_key


def get_vault_ca_certificate(juju: jubilant.Juju, unit_name: str) -> str:
    task = juju.exec("cat /var/lib/juju/storage/certs/0/ca.pem", unit=unit_name)
    return task.stdout


def refresh_application(juju: jubilant.Juju, app_name: str, charm_path: Path) -> None:
    juju.refresh(app_name, path=charm_path)


def scale(juju: jubilant.Juju, app_name: str, target: int) -> None:
    """Scale a K8s application to the target number of units."""
    status = juju.status()
    current = len(status.apps[app_name].units)
    if current < target:
        juju.add_unit(app_name, num_units=target - current)
    elif current > target:
        juju.remove_unit(app_name, num_units=current - target)


@contextlib.contextmanager
def fast_forward(
    juju: jubilant.Juju, fast_interval: str = JUJU_FAST_INTERVAL
) -> Generator[None, None, None]:
    """Context manager that sets a fast update-status interval and resets it on exit."""
    juju.model_config({"update-status-hook-interval": fast_interval})
    try:
        yield
    finally:
        juju.model_config(reset="update-status-hook-interval")


def configure_s3_and_create_backup(
    juju: jubilant.Juju,
    root_token: str,
    app_name: str = APPLICATION_NAME,
) -> None:
    """Configure S3 and create a backup."""
    task = juju.run(f"{app_name}/leader", "create-backup", wait=300)
    task.raise_on_failure()


def list_backups(juju: jubilant.Juju, app_name: str = APPLICATION_NAME) -> List[str]:
    """List all backups."""
    task = juju.run(f"{app_name}/leader", "list-backups", wait=120)
    task.raise_on_failure()
    backups_str = task.results.get("backups", "")
    if not backups_str:
        return []
    return [b.strip() for b in backups_str.split(",") if b.strip()]


def restore_backup(
    juju: jubilant.Juju,
    backup_name: str,
    root_token: str,
    app_name: str = APPLICATION_NAME,
) -> None:
    """Restore a backup."""
    task = juju.run(
        f"{app_name}/leader",
        "restore-backup",
        {"backup-name": backup_name},
        wait=300,
    )
    task.raise_on_failure()


def run_action_on_leader(
    juju: jubilant.Juju,
    app_name: str,
    action_name: str,
    **kwargs: Any,
) -> Any:
    """Run an action on the leader unit."""
    return juju.run(f"{app_name}/leader", action_name, kwargs, wait=120)
