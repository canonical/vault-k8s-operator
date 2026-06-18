#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import contextlib
import json
import logging
import os
import platform
import tempfile
import time
from pathlib import Path
from typing import Any, List, Tuple

import jubilant
from cryptography import x509

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
)
from vault_helpers import Vault

logger = logging.getLogger(__name__)


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


@contextlib.contextmanager
def fast_forward(juju: jubilant.Juju, fast_interval: str = JUJU_FAST_INTERVAL):
    juju.model_config({"update-status-hook-interval": fast_interval})
    try:
        yield
    finally:
        juju.model_config(reset="update-status-hook-interval")


def scale(juju: jubilant.Juju, app_name: str, target: int) -> None:
    status = juju.status()
    current = len(status.apps[app_name].units)
    if current < target:
        juju.add_unit(app_name, num_units=target - current)
    elif current > target:
        juju.remove_unit(app_name, num_units=current - target)


def get_leader_unit_name(juju: jubilant.Juju, app_name: str) -> str:
    """Return the leader unit name for the given application."""
    status = juju.status()
    for unit_name, unit in status.apps[app_name].units.items():
        if unit.leader:
            return unit_name
    raise RuntimeError(f"Leader unit for `{app_name}` not found.")


def get_unit_address(juju: jubilant.Juju, unit_name: str) -> str:
    """Return the address of the given unit."""
    app_name = unit_name.split("/")[0]
    status = juju.status()
    return status.apps[app_name].units[unit_name].public_address


def get_first(d: dict) -> Any:
    return next(iter(d.values()))


def has_relation(juju: jubilant.Juju, app_name: str, relation_name: str) -> bool:
    """Check if the application has the relation with the given name."""
    status = juju.status()
    if app_name not in status.apps:
        return False
    return relation_name in status.apps[app_name].relations


def get_ca_cert_file_location(juju: jubilant.Juju, app_name: str = APP_NAME) -> str | None:
    """Get the location of the CA certificate file."""
    if not has_relation(juju, app_name, "tls-certificates-access"):
        return None
    action_output = run_get_ca_certificate_action(juju)
    ca_certificate = action_output["ca-certificate"]
    assert ca_certificate
    ca_file_location = os.path.join(tempfile.gettempdir(), f"ca_file_{app_name}.txt")
    with open(ca_file_location, mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    return ca_file_location


def run_get_ca_certificate_action(juju: jubilant.Juju, timeout: int = 60) -> dict:
    """Run the `get-ca-certificate` on the `self-signed-certificates` unit."""
    return juju.run(
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0",
        "get-ca-certificate",
        {},
        wait=timeout,
    ).results


def authorize_charm(juju: jubilant.Juju, root_token: str, app_name: str = APP_NAME) -> Any:
    """Authorize the charm to interact with Vault."""
    status = juju.status()
    if jubilant.all_active(status, app_name):
        logger.info("The charm is already active, skipping authorization.")
        return
    logger.info("Authorizing the charm `%s` to interact with Vault.", app_name)
    secret_name = f"approle-token-{app_name}"
    secret_uri = juju.add_secret(secret_name, {"token": root_token})
    secret_id = secret_uri.split(":")[-1]
    juju.grant_secret(secret_name, app_name)
    return run_action_on_leader(juju, app_name, "authorize-charm", secret_id=secret_id)


def authorize_charm_and_wait(
    juju: jubilant.Juju, root_token: str, app_name: str = APP_NAME
) -> Any:
    """Authorize the charm and wait for it to be authorized."""
    result = authorize_charm(juju, root_token, app_name)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, app_name),
            timeout=60,
            error=None,
        )
    logger.info("Charm authorized")
    return result


def get_vault_token_and_unseal_key(
    juju: jubilant.Juju, app_name: str = APP_NAME
) -> Tuple[str, str]:
    root_token, unseal_key = get_juju_secret(
        juju, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, unseal_key


def initialize_vault_leader(juju: jubilant.Juju, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key."""
    leader_name = get_leader_unit_name(juju, app_name)
    vault = get_vault_client(juju, leader_name)
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        juju.add_secret(
            f"root-token-key-{app_name}",
            {"root-token": root_token, "key": key},
        )
        return root_token, key
    root_token, key = get_vault_token_and_unseal_key(juju, app_name)
    return root_token, key


def get_vault_client(
    juju: jubilant.Juju,
    unit_name: str,
    token: str | None = None,
    ca_file_name: str | None = None,
) -> Vault:
    """Get a Vault client for the given unit."""
    app_name = unit_name.split("/")[0]
    address = juju.status().apps[app_name].units[unit_name].public_address
    return Vault(url=f"https://{address}:8200", token=token, ca_file_location=ca_file_name)


def unseal_all_vault_units(
    juju: jubilant.Juju, unseal_key: str, ca_file_name: str | None = None
) -> None:
    """Unseal all the vault units."""
    status = juju.status()
    app = status.apps[APP_NAME]

    # We need to unseal the leader first, since this is the one we initialized.
    leader_name = get_leader_unit_name(juju, APP_NAME)
    unit_address = app.units[leader_name].public_address
    assert unit_address
    vault = Vault(url=f"https://{unit_address}:8200")
    if vault.is_sealed():
        vault.unseal(unseal_key)
    vault.wait_for_node_to_be_unsealed()

    for unit_name, unit in app.units.items():
        unit_address = unit.public_address
        assert unit_address
        vault = Vault(url=f"https://{unit_address}:8200", ca_file_location=ca_file_name)
        vault.unseal(unseal_key)
        vault.wait_for_node_to_be_unsealed()


def initialize_unseal_authorize_vault(juju: jubilant.Juju, app_name: str) -> tuple[str, str]:
    root_token, unseal_key = initialize_vault_leader(juju, app_name)
    leader_name = get_leader_unit_name(juju, app_name)
    vault = get_vault_client(juju, leader_name, root_token)
    assert vault.is_sealed()

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, unseal_key)
        authorize_charm_and_wait(juju, root_token)
    return root_token, unseal_key


def run_get_certificate_action(juju: jubilant.Juju) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit."""
    return juju.run(
        f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0",
        "get-certificate",
        {},
        wait=30,
    ).results


def wait_for_certificate_to_be_provided(juju: jubilant.Juju) -> None:
    start_time = time.time()
    timeout = 300
    while time.time() - start_time < timeout:
        try:
            action_output = run_get_certificate_action(juju)
        except jubilant.TaskError:
            time.sleep(10)
            continue
        if action_output.get("certificate", None) is not None:
            return
        time.sleep(10)
    raise TimeoutError("Timed out waiting for certificate to be provided.")


def wait_for_status_message(
    juju: jubilant.Juju,
    expected_message: str,
    app_name: str = APP_NAME,
    count: int = 1,
    timeout: int = 100,
    cadence: int = 2,
) -> None:
    """Wait for the correct status messages to appear.

    Args:
        juju: Jubilant Juju instance
        app_name: Application name of the Vault, defaults to APP_NAME
        count: How many units are expected to be emitting the message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time, in seconds, before giving up
        cadence: How often to check the status of the units
    """

    def ready(status: jubilant.Status) -> bool:
        if app_name not in status.apps:
            return False
        units = status.apps[app_name].units
        seen = sum(1 for u in units.values() if u.workload_status.message == expected_message)
        return seen == count

    juju.wait(ready, timeout=timeout, delay=cadence)


def deploy_vault(
    juju: jubilant.Juju,
    num_vaults: int,
    channel: str | None = None,
    charm_path: Path | None = None,
    revision: int | None = None,
) -> None:
    """Ensure the Vault charm is deployed."""
    deploy_if_not_exists(
        juju,
        app_name=APP_NAME,
        charm_path=charm_path,
        num_units=num_vaults,
        channel=channel,
        revision=revision,
        constraints={"arch": _get_arch()},
    )


def deploy_vault_and_wait(
    juju: jubilant.Juju,
    num_units: int,
    status: str | None = None,
    channel: str | None = None,
    charm_path: Path | None = None,
    revision: int | None = None,
) -> None:
    deploy_vault(
        juju, num_vaults=num_units, channel=channel, charm_path=charm_path, revision=revision
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        if status == "blocked":
            juju.wait(
                lambda s: (
                    APP_NAME in s.apps
                    and jubilant.all_blocked(s, APP_NAME)
                    and len(s.apps[APP_NAME].units) >= num_units
                ),
                timeout=1000,
            )
        elif status == "active":
            juju.wait(
                lambda s: (
                    APP_NAME in s.apps
                    and jubilant.all_active(s, APP_NAME)
                    and len(s.apps[APP_NAME].units) >= num_units
                ),
                timeout=1000,
            )
        else:
            juju.wait(
                lambda s: APP_NAME in s.apps and len(s.apps[APP_NAME].units) >= num_units,
                timeout=1000,
            )


def get_leader_unit_address(juju: jubilant.Juju, app_name: str = APP_NAME) -> str:
    leader_name = get_leader_unit_name(juju, app_name)
    address = juju.status().apps[app_name].units[leader_name].public_address
    assert address
    return address


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
    series: str | None = None,
    trust: bool = False,
    constraints: dict | None = None,
) -> None:
    status = juju.status()
    if app_name in status.apps:
        return
    kwargs: dict[str, Any] = {}
    if config:
        kwargs["config"] = config
    if channel:
        kwargs["channel"] = channel
    if revision:
        kwargs["revision"] = revision
    if series:
        kwargs["base"] = series
    if trust:
        kwargs["trust"] = trust
    if constraints:
        kwargs["constraints"] = constraints
    try:
        juju.deploy(
            charm_path if charm_path else app_name,
            app_name,
            num_units=num_units,
            **kwargs,
        )
    except jubilant.CLIError as e:
        if "already exists" in (e.stderr or ""):
            logger.warning("Application `%s` already exists, skipping deploy", app_name)
            return
        raise


def get_juju_secret(juju: jubilant.Juju, label: str, fields: List[str]) -> List[str]:
    secrets = juju.secrets()
    try:
        secret = next(s for s in secrets if s.label == label)
        revealed = juju.show_secret(secret.uri, reveal=True)
    except StopIteration:
        # Fallback: look up directly by label in case juju.secrets() listing is incomplete
        revealed = juju.show_secret(label, reveal=True)
    return [revealed.content[field] for field in fields]


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


def run_action_on_leader(
    juju: jubilant.Juju,
    app_name: str,
    action_name: str,
    raise_on_error: bool = True,
    **kwargs: Any,
) -> dict:
    """Run an action on the leader unit of the given application.

    Wait for the action to complete and return the output.

    Args:
        juju: The Jubilant Juju instance.
        app_name: The name of the application to run the action on.
        action_name: The name of the action to run.
        raise_on_error: Whether to raise an error if the action fails.
        **kwargs: Additional keyword arguments. Underscores replaced with dashes.

    Returns:
        dict: The output of the action.
    """
    kwargs = {k.replace("_", "-"): v for k, v in kwargs.items()}
    task = juju.run(f"{app_name}/leader", action_name, kwargs, wait=120)
    logger.info(
        "Action `%s` on `%s/leader` completed with status `%s`. Results: %s",
        action_name,
        app_name,
        task.status,
        task.results,
    )
    if raise_on_error and task.status != "completed":
        raise ActionFailedError(f"Action {action_name} failed with status `{task.status}`.")
    return task.results


def refresh_application(juju: jubilant.Juju, app_name: str, charm_path: Path) -> None:
    juju.refresh(app_name, path=charm_path)


def configure_s3_and_create_backup(
    juju: jubilant.Juju,
    root_token: str,
    s3_endpoint: str,
    s3_access_key: str,
    s3_secret_key: str,
    s3_bucket: str,
    s3_region: str,
    kv_secret_value: str,
) -> None:
    """Configure the S3 integrator, write a KV secret, and create a backup."""
    run_action_on_leader(
        juju,
        S3_INTEGRATOR_APPLICATION_NAME,
        "sync-s3-credentials",
        access_key=s3_access_key,
        secret_key=s3_secret_key,
    )

    s3_config = {
        "endpoint": s3_endpoint,
        "bucket": s3_bucket,
        "region": s3_region,
    }
    juju.config(S3_INTEGRATOR_APPLICATION_NAME, s3_config)
    juju.wait(
        lambda s: jubilant.all_active(s, S3_INTEGRATOR_APPLICATION_NAME),
        timeout=SHORT_TIMEOUT,
    )

    if not has_relation(juju, APP_NAME, "s3-parameters"):
        juju.integrate(APP_NAME, S3_INTEGRATOR_APPLICATION_NAME)
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
                and all(u.juju_status.current == "idle" for u in s.apps[APP_NAME].units.values())
            ),
            timeout=SHORT_TIMEOUT,
        )

    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, root_token)
    vault.enable_kv_engine(path="kv/", description="Test KV Engine")
    vault.write("kv/secret", {"key": kv_secret_value})

    run_action_on_leader(juju, APP_NAME, "create-backup", skip_verify=True)


def list_backups(juju: jubilant.Juju) -> list[str]:
    """List backups and return the backup IDs."""
    results = run_action_on_leader(juju, APP_NAME, "list-backups", skip_verify=True)
    assert results["backup-ids"] is not None
    backup_ids = json.loads(results["backup-ids"])
    assert len(backup_ids) > 0
    return backup_ids


def restore_backup(
    juju: jubilant.Juju,
    root_token: str,
    kv_secret_value: str,
) -> None:
    """Restore the most recent backup and verify the KV secret is restored."""
    backup_ids = list_backups(juju)
    backup_id = backup_ids[-1]

    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, root_token)

    assert vault.read("kv/secret") == {"key": kv_secret_value}
    vault.delete("kv/secret")
    assert vault.read("kv/secret") is None

    backup_action_output = run_action_on_leader(
        juju, APP_NAME, "restore-backup", skip_verify=True, backup_id=backup_id
    )

    assert vault.read("kv/secret") == {"key": kv_secret_value}
    assert backup_action_output["restored"] == backup_id
