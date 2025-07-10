from asyncio import Task, create_task

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
)
from helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def self_signed_certificates_idle(ops_test: OpsTest) -> Task:
    """Deploy the `self-signed-certificates` charm."""

    async def deploy_self_signed_certificates(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model,
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            channel="1/stable",
            revision=SELF_SIGNED_CERTIFICATES_REVISION,
        )
        async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
            await ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            )

    return create_task(deploy_self_signed_certificates(ops_test))
