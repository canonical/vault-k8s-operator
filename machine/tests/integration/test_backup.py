import pytest
from pytest_operator.plugin import OpsTest

from config import MINIO_S3_ACCESS_KEY, MINIO_S3_SECRET_KEY
from helpers import VaultInit, configure_s3_and_create_backup, list_backups, restore_backup


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    ops_test: OpsTest,
    deploy: VaultInit,
    host_ip: str,
):
    await configure_s3_and_create_backup(
        ops_test,
        root_token=deploy.root_token,
        s3_endpoint=f"https://{host_ip}:8555",
        s3_access_key=MINIO_S3_ACCESS_KEY,
        s3_secret_key=MINIO_S3_SECRET_KEY,
        s3_bucket="vault-integration-test",
        s3_region="local",
        kv_secret_value="value",
    )


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    ops_test: OpsTest, deploy: VaultInit
):
    await list_backups(ops_test)


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    ops_test: OpsTest,
    deploy: VaultInit,
):
    await restore_backup(
        ops_test,
        root_token=deploy.root_token,
        kv_secret_value="value",
    )
