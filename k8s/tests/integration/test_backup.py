# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    MINIO_APPLICATION_NAME,
    MINIO_REVISION,
    MINIO_S3_ACCESS_KEY,
    MINIO_S3_SECRET_KEY,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    S3_INTEGRATOR_REVISION,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

logger = logging.getLogger(__name__)


VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )
    juju.deploy(
        S3_INTEGRATOR_APPLICATION_NAME,
        channel="stable",
        revision=S3_INTEGRATOR_REVISION,
        trust=True,
    )
    juju.deploy(
        MINIO_APPLICATION_NAME,
        channel="ckf-1.9/stable",
        revision=MINIO_REVISION,
        config={
            "access-key": MINIO_S3_ACCESS_KEY,
            "secret-key": MINIO_S3_SECRET_KEY,
        },
        trust=True,
    )

    juju.wait(
        lambda s: (
            APPLICATION_NAME in s.apps
            and S3_INTEGRATOR_APPLICATION_NAME in s.apps
            and MINIO_APPLICATION_NAME in s.apps
            and jubilant.all_blocked(s, APPLICATION_NAME)
            and jubilant.all_active(s, MINIO_APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
    )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


def _run_s3_integrator_sync_credentials(juju: jubilant.Juju) -> None:
    """Run sync-s3-credentials action on the s3-integrator leader."""
    task = juju.run(
        f"{S3_INTEGRATOR_APPLICATION_NAME}/leader",
        "sync-s3-credentials",
        {"access-key": MINIO_S3_ACCESS_KEY, "secret-key": MINIO_S3_SECRET_KEY},
        wait=120,
    )
    task.raise_on_failure()


def _run_create_backup_action(juju: jubilant.Juju) -> dict:
    """Run create-backup action on the vault leader unit."""
    task = juju.run(
        f"{APPLICATION_NAME}/leader",
        "create-backup",
        wait=120,
    )
    task.raise_on_failure()
    return task.results


def _run_list_backups_action(juju: jubilant.Juju) -> dict:
    """Run list-backups action on the vault leader unit."""
    task = juju.run(
        f"{APPLICATION_NAME}/leader",
        "list-backups",
        wait=120,
    )
    task.raise_on_failure()
    return task.results


def _run_restore_backup_action(juju: jubilant.Juju, backup_id: str) -> dict:
    """Run restore-backup action on the vault leader unit."""
    task = juju.run(
        f"{APPLICATION_NAME}/leader",
        "restore-backup",
        {"backup-id": backup_id},
        wait=120,
    )
    return task.results


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_and_related_to_s3_integrator_when_create_backup_action_then_backup_is_created(
    juju: jubilant.Juju, deploy: VaultInit
):
    _run_s3_integrator_sync_credentials(juju)

    endpoint = f"http://{MINIO_APPLICATION_NAME}:9000"

    s3_config = {
        "endpoint": endpoint,
        "bucket": "test-bucket",
        "region": "local",
    }
    juju.config(S3_INTEGRATOR_APPLICATION_NAME, s3_config)
    juju.wait(
        lambda s: jubilant.all_active(s, S3_INTEGRATOR_APPLICATION_NAME),
        timeout=SHORT_TIMEOUT,
    )
    juju.integrate(
        APPLICATION_NAME,
        S3_INTEGRATOR_APPLICATION_NAME,
    )
    juju.wait(
        lambda s: (
            jubilant.all_active(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            and all(
                u.juju_status.current == "idle" for u in s.apps[APPLICATION_NAME].units.values()
            )
        ),
        timeout=SHORT_TIMEOUT,
    )
    create_backup_output = _run_create_backup_action(juju)
    assert create_backup_output["backup-id"], create_backup_output


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_and_backup_created_when_list_backups_action_then_backups_are_listed(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.wait(
        lambda s: (
            jubilant.all_active(s, S3_INTEGRATOR_APPLICATION_NAME)
            and jubilant.all_active(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=SHORT_TIMEOUT,
    )
    list_backups_output = _run_list_backups_action(juju)
    backup_ids = json.loads(list_backups_output["backup-ids"])
    assert backup_ids, f"Expected non-empty backup list, got: {list_backups_output}"


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_and_backup_created_when_restore_backup_action_then_backup_is_restored(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.wait(
        lambda s: (
            jubilant.all_active(s, S3_INTEGRATOR_APPLICATION_NAME)
            and jubilant.all_active(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=SHORT_TIMEOUT,
    )
    list_backups_output = _run_list_backups_action(juju)
    backup_id = json.loads(list_backups_output["backup-ids"])[0]
    restore_output = _run_restore_backup_action(juju, backup_id=backup_id)
    assert restore_output.get("restored") == backup_id
