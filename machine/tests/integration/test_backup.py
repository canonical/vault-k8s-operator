# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    get_app,
    has_relation,
)
from tests.integration.integration_support import (
    APP_NAME,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    run_create_backup_action,
    run_list_backups_action,
    run_restore_backup_action,
    run_s3_integrator_sync_credentials_action,
)


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await s3_integrator_idle

    s3_integrator = get_app(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
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
        timeout=1000,
    )
    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    create_backup_action_output = await run_create_backup_action(ops_test)
    assert create_backup_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    await vault_authorized
    await s3_integrator_idle
    assert ops_test.model

    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    list_backups_action_output = await run_list_backups_action(ops_test)
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

    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    backup_id = "dummy-backup-id"

    backup_action_output = await run_restore_backup_action(ops_test, backup_id)
    assert backup_action_output.get("return-code") == 0
