import asyncio
import json
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APPLICATION_NAME,
    MINIO_APPLICATION_NAME,
    MINIO_S3_ACCESS_KEY,
    MINIO_S3_SECRET_KEY,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    get_leader_unit,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

logger = logging.getLogger(__name__)


VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APPLICATION_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        S3_INTEGRATOR_APPLICATION_NAME,
        application_name=S3_INTEGRATOR_APPLICATION_NAME,
        channel="stable",
        trust=True,
    )
    await ops_test.model.deploy(
        MINIO_APPLICATION_NAME,
        application_name=MINIO_APPLICATION_NAME,
        channel="ckf-1.9/stable",
        config={
            "access-key": MINIO_S3_ACCESS_KEY,
            "secret-key": MINIO_S3_SECRET_KEY,
        },
        trust=True,
    )

    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME, MINIO_APPLICATION_NAME],
            timeout=120,  # These should be quick to deploy
        ),
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
    )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_application_is_deployed_and_related_to_s3_integrator_when_create_backup_action_then_backup_is_created(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    status = await ops_test.model.get_status()
    minio_app = status.applications[MINIO_APPLICATION_NAME]
    assert minio_app
    minio_unit = minio_app.units[f"{MINIO_APPLICATION_NAME}/0"]
    assert minio_unit
    minio_ip = minio_unit.address
    endpoint = f"http://{minio_ip}:9000"
    s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
    assert s3_integrator
    output = await run_s3_integrator_sync_credentials_action(
        ops_test,
        secret_key=MINIO_S3_SECRET_KEY,
        access_key=MINIO_S3_ACCESS_KEY,
    )
    logger.info("S3 Integrator sync credentials action output: %s", output)
    s3_config = {
        "endpoint": endpoint,
        "bucket": "test-bucket",
        "region": "local",
    }
    await s3_integrator.set_config(s3_config)
    await ops_test.model.wait_for_idle(
        apps=[S3_INTEGRATOR_APPLICATION_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
    )
    await ops_test.model.integrate(
        relation1=APPLICATION_NAME,
        relation2=S3_INTEGRATOR_APPLICATION_NAME,
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    create_backup_action_output = await run_create_backup_action(ops_test)
    assert create_backup_action_output["backup-id"], create_backup_action_output


@pytest.mark.abort_on_fail
async def test_given_application_is_deployed_and_backup_created_when_list_backups_action_then_backups_are_listed(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        ),
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
    )
    list_backups_action_output = await run_list_backups_action(ops_test)
    assert list_backups_action_output["backup-ids"]


@pytest.mark.abort_on_fail
async def test_given_application_is_deployed_and_backup_created_when_restore_backup_action_then_backup_is_restored(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        ),
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
    )
    list_backups_action_output = await run_list_backups_action(ops_test)
    backup_id = json.loads(list_backups_action_output["backup-ids"])[0]
    # In this test we are not using the correct unsealed keys and root token.
    restore_backup_action_output = await run_restore_backup_action(ops_test, backup_id=backup_id)
    assert restore_backup_action_output.get("return-code") == 0
    assert not restore_backup_action_output.get("stderr", None)
    assert restore_backup_action_output.get("restored", None) == backup_id


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
