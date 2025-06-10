from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_APPLICATION_NAME,
)
from tests.integration.helpers import get_leader_unit, has_relation


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
    vault_kv_unit = await get_leader_unit(ops_test.model, VAULT_KV_REQUIRER_APPLICATION_NAME)
    vault_kv_create_secret_action = await vault_kv_unit.run_action(
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    await ops_test.model.get_action_output(
        action_uuid=vault_kv_create_secret_action.entity_id, wait=30
    )

    vault_kv_get_secret_action = await vault_kv_unit.run_action(
        action_name="get-secret",
        key=secret_key,
    )

    action_output = await ops_test.model.get_action_output(
        action_uuid=vault_kv_get_secret_action.entity_id, wait=30
    )

    assert action_output["value"] == secret_value
