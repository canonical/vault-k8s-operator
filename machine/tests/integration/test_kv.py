from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_APPLICATION_NAME,
)
from tests.integration.helpers import has_relation, run_action_on_leader


@pytest.mark.dependency
@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, vault_kv_requirer_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await vault_kv_requirer_idle

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
    ops_test: OpsTest, vault_authorized: Task, vault_kv_requirer_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await vault_kv_requirer_idle

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
