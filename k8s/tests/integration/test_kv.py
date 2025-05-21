from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME


@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, vault_kv_requirer_1_idle: Task, vault_authorized: Task
):
    await vault_kv_requirer_1_idle
    await vault_authorized

    assert ops_test.model

    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:vault-kv",
        relation2=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}:vault-kv",
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )
