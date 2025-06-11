from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    GRAFANA_AGENT_APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    SHORT_TIMEOUT,
)


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, grafana_deployed: Task
):
    assert ops_test.model
    await vault_authorized
    await grafana_deployed

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:cos-agent",
        relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=SHORT_TIMEOUT,
            status="active",
        )
