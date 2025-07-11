from asyncio import Task, create_task

import pytest
from pytest_operator.plugin import OpsTest

from config import GRAFANA_AGENT_APPLICATION_NAME
from helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def grafana_deployed(ops_test: OpsTest) -> Task:
    """Deploy the `grafana-agent` charm."""
    assert ops_test.model

    return create_task(
        deploy_if_not_exists(
            ops_test.model, GRAFANA_AGENT_APPLICATION_NAME, series="noble", channel="1/stable"
        )
    )
