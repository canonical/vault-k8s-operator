import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_APPLICATION_NAME,
)
from helpers import (
    deploy_vault,
    get_vault_token_and_unseal_key,
    has_relation,
    initialize_unseal_authorize_vault,
    run_action_on_leader,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(
    ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool, kv_requirer_charm_path: Path
) -> VaultInit:
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
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    await ops_test.model.deploy(
        kv_requirer_charm_path, application_name=VAULT_KV_REQUIRER_APPLICATION_NAME
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[
                    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
                    VAULT_KV_REQUIRER_APPLICATION_NAME,
                ],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.dependency
@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    vault_app = ops_test.model.applications[APP_NAME]
    if not has_relation(vault_app, "vault-kv"):
        await ops_test.model.integrate(
            relation1=f"{APP_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
        )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.dependency(
    depends=[
        "test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active"
    ]
)
@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    secret_key = "test-key"
    secret_value = "test-value"
    await run_action_on_leader(
        ops_test,
        VAULT_KV_REQUIRER_APPLICATION_NAME,
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    vault_kv_get_secret_action = await run_action_on_leader(
        ops_test,
        VAULT_KV_REQUIRER_APPLICATION_NAME,
        action_name="get-secret",
        key=secret_key,
    )

    assert vault_kv_get_secret_action["value"] == secret_value
