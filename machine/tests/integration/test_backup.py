import asyncio
import json
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    MINIO_S3_ACCESS_KEY,
    MINIO_S3_SECRET_KEY,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from tests.integration.helpers import (
    deploy_vault,
    get_leader_unit,
    get_vault_client,
    get_vault_token_and_unseal_key,
    has_relation,
    initialize_unseal_authorize_vault,
    run_action_on_leader,
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
        application_name=S3_INTEGRATOR_APPLICATION_NAME,
        channel="stable",
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
    assert ops_test.model

    await run_action_on_leader(
        ops_test,
        S3_INTEGRATOR_APPLICATION_NAME,
        "sync-s3-credentials",
        access_key=MINIO_S3_ACCESS_KEY,
        secret_key=MINIO_S3_SECRET_KEY,
    )

    s3_config = {
        "endpoint": f"https://{host_ip}:8555",
        "bucket": "vault-integration-test",
        "region": "local",
    }
    s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
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
    # Put a secret in the KV store so we have something to back up.
    leader = await get_leader_unit(ops_test.model, APP_NAME)
    vault = await get_vault_client(ops_test, leader, deploy.root_token)
    vault.enable_kv_engine(path="kv/", description="Test KV Engine")
    vault.write("kv/secret", {"key": "value"})

    await run_action_on_leader(ops_test, APP_NAME, "create-backup", skip_verify=True)


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    results = await run_action_on_leader(ops_test, APP_NAME, "list-backups", skip_verify=True)
    assert results["backup-ids"] is not None
    assert len(json.loads(results["backup-ids"])) > 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    ops_test: OpsTest,
    deploy: VaultInit,
):
    assert ops_test.model

    list_backups_output = await run_action_on_leader(
        ops_test, APP_NAME, "list-backups", skip_verify=True
    )

    # Get the most recent backup ID
    backup_id = json.loads(list_backups_output["backup-ids"])[-1]

    leader = await get_leader_unit(ops_test.model, APP_NAME)
    vault = await get_vault_client(ops_test, leader, deploy.root_token)
    # Verify the secret is there
    assert vault.read("kv/secret") == {"key": "value"}
    vault.delete("kv/secret")

    # Ensure the secret is deleted before restoring
    assert vault.read("kv/secret") is None

    backup_action_output = await run_action_on_leader(
        ops_test, APP_NAME, "restore-backup", skip_verify=True, backup_id=backup_id
    )

    # Check that the secret is restored
    assert vault.read("kv/secret") == {"key": "value"}
    assert backup_action_output["restored"] == backup_id
