# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.integration_support import (
    APP_NAME,
    GRAFANA_AGENT_APPLICATION_NAME,
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
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=1000,
            status="active",
        )
