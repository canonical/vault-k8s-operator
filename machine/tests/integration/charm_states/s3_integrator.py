from asyncio import Task, create_task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.constants import S3_INTEGRATOR_APPLICATION_NAME
from tests.integration.helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def s3_integrator_idle(ops_test: OpsTest) -> Task:
    """Deploy the `s3-integrator` charm."""

    async def deploy_s3_integrator(ops_test: OpsTest):
        assert ops_test.model

        await deploy_if_not_exists(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
        )

    return create_task(deploy_s3_integrator(ops_test))
