from asyncio import Task, create_task
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import VAULT_KV_REQUIRER_APPLICATION_NAME
from tests.integration.helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def vault_kv_requirer_idle(ops_test: OpsTest, kv_requirer_charm_path: Path) -> Task:
    """Deploy the `vault-kv-requirer` charm."""

    async def deploy_kv_requirer(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model, VAULT_KV_REQUIRER_APPLICATION_NAME, charm_path=kv_requirer_charm_path
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[VAULT_KV_REQUIRER_APPLICATION_NAME],
            )

    return create_task(deploy_kv_requirer(ops_test))
