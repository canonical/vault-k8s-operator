import jubilant
import pytest

from config import MINIO_S3_ACCESS_KEY, MINIO_S3_SECRET_KEY
from helpers import VaultInit, configure_s3_and_create_backup, list_backups, restore_backup


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    juju: jubilant.Juju,
    deploy: VaultInit,
    host_ip: str,
):
    configure_s3_and_create_backup(
        juju,
        root_token=deploy.root_token,
        s3_endpoint=f"https://{host_ip}:8555",
        s3_access_key=MINIO_S3_ACCESS_KEY,
        s3_secret_key=MINIO_S3_SECRET_KEY,
        s3_bucket="vault-integration-test",
        s3_region="local",
        kv_secret_value="value",
    )


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    juju: jubilant.Juju, deploy: VaultInit
):
    list_backups(juju)


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    restore_backup(
        juju,
        root_token=deploy.root_token,
        kv_secret_value="value",
    )
