from asyncio import Task, create_task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import HAPROXY_APPLICATION_NAME
from tests.integration.helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def haproxy_idle(ops_test: OpsTest) -> Task:
    """Deploy the `haproxy` charm."""

    async def deploy_haproxy(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(ops_test.model, HAPROXY_APPLICATION_NAME, channel="2.8/edge")
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[HAPROXY_APPLICATION_NAME],
            )

    return create_task(deploy_haproxy(ops_test))
