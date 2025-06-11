from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from tests.integration.helpers import get_leader_unit, has_relation


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


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await s3_integrator_idle

    s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
    await run_s3_integrator_sync_credentials_action(
        ops_test,
        secret_key="Dummy secret key",
        access_key="Dummy access key",
    )
    s3_config = {
        "endpoint": "http://minio-dummy:9000",
        "bucket": "test-bucket",
        "region": "local",
    }
    await s3_integrator.set_config(s3_config)
    await ops_test.model.wait_for_idle(
        apps=[S3_INTEGRATOR_APPLICATION_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
    )
    vault_app = ops_test.model.applications[APP_NAME]
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    create_backup_action_output = await run_create_backup_action(ops_test)
    # FIXME: The action return code is always 0. This test doesn't work as expected.
    # We aren't even deploying minio.
    # https://github.com/canonical/vault-k8s-operator/issues/653
    assert create_backup_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    await vault_authorized
    await s3_integrator_idle
    assert ops_test.model

    vault_app = ops_test.model.applications[APP_NAME]
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    list_backups_action_output = await run_list_backups_action(ops_test)
    # FIXME: The action return code is always 0. This test doesn't work as expected.
    # We aren't even deploying minio.
    # https://github.com/canonical/vault-k8s-operator/issues/653
    assert list_backups_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    ops_test: OpsTest,
    vault_authorized: Task,
    s3_integrator_idle: Task,
    self_signed_certificates_idle: Task,
):
    assert ops_test.model
    await vault_authorized
    await s3_integrator_idle
    await self_signed_certificates_idle

    vault_app = ops_test.model.applications[APP_NAME]
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )
    backup_id = "dummy-backup-id"

    backup_action_output = await run_restore_backup_action(ops_test, backup_id)
    # FIXME: The action return code is always 0. This test doesn't work as expected.
    # We areon't even deploying minio.
    # https://github.com/canonical/vault-k8s-operator/issues/653
    assert backup_action_output.get("return-code") == 0
