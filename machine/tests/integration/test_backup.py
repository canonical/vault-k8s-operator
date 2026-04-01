import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    MINIO_S3_ACCESS_KEY,
    MINIO_S3_SECRET_KEY,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    S3_INTEGRATOR_REVISION,
)
from helpers import (
    configure_s3_and_create_backup,
    deploy_vault,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    list_backups,
    restore_backup,
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
            APP_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        S3_INTEGRATOR_APPLICATION_NAME,
        channel="stable",
        revision=S3_INTEGRATOR_REVISION,
        trust=True,
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[S3_INTEGRATOR_APPLICATION_NAME],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


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
