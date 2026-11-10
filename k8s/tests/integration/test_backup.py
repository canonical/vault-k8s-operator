# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
from typing import Tuple

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.integration_support import (
    APPLICATION_NAME,
    MINIO_APPLICATION_NAME,
    MINIO_CONFIG,
    MINIO_S3_ACCESS_KEY,
    MINIO_S3_SECRET_KEY,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    run_create_backup_action,
    run_list_backups_action,
    run_restore_backup_action,
    run_s3_integrator_sync_credentials_action,
)


class TestVaultBackup:
    """Exercise backup behavior."""

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        deploy_s3_integrator = ops_test.model.deploy(
            "s3-integrator",
            application_name=S3_INTEGRATOR_APPLICATION_NAME,
            trust=True,
            channel="1/stable",
        )
        deploy_minio = ops_test.model.deploy(
            "minio",
            application_name=MINIO_APPLICATION_NAME,
            trust=True,
            config=MINIO_CONFIG,
            channel="ckf-1.10/stable",
        )
        await asyncio.gather(
            deploy_s3_integrator,
            deploy_minio,
        )
        deployed_apps = [
            S3_INTEGRATOR_APPLICATION_NAME,
            MINIO_APPLICATION_NAME,
        ]
        await ops_test.model.wait_for_idle(
            apps=[MINIO_APPLICATION_NAME],
            status="active",
            timeout=600,
            wait_for_at_least_units=1,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_related_to_s3_integrator_when_create_backup_action_then_backup_is_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[MINIO_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )
        status = await ops_test.model.get_status()
        minio_app = status.applications[MINIO_APPLICATION_NAME]
        assert minio_app
        minio_unit = minio_app.units[f"{MINIO_APPLICATION_NAME}/0"]  # pyright: ignore [reportAttributeAccessIssue] Regression in pyright 1.1.392/393
        assert minio_unit
        minio_ip = minio_unit.address
        endpoint = f"http://{minio_ip}:9000"
        s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
        assert s3_integrator
        await run_s3_integrator_sync_credentials_action(
            ops_test,
            secret_key=MINIO_S3_SECRET_KEY,
            access_key=MINIO_S3_ACCESS_KEY,
        )
        s3_config = {
            "endpoint": endpoint,
            "bucket": "test-bucket",
            "region": "local",
        }
        await s3_integrator.set_config(s3_config)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.integrate(
            relation1=APPLICATION_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        create_backup_action_output = await run_create_backup_action(ops_test)
        assert create_backup_action_output["backup-id"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_list_backups_action_then_backups_are_listed(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await run_list_backups_action(ops_test)
        assert list_backups_action_output["backup-ids"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_restore_backup_action_then_backup_is_restored(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await run_list_backups_action(ops_test)
        backup_id = json.loads(list_backups_action_output["backup-ids"])[0]
        # In this test we are not using the correct unsealed keys and root token.
        restore_backup_action_output = await run_restore_backup_action(
            ops_test, backup_id=backup_id
        )
        assert restore_backup_action_output.get("return-code") == 0
        assert not restore_backup_action_output.get("stderr", None)
        assert restore_backup_action_output.get("restored", None) == backup_id
