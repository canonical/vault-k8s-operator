# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from asyncio import Task, gather

from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    get_app,
)
from tests.integration.integration_support import (
    APP_NAME,
    HAPROXY_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
)


async def test_given_haproxy_deployed_when_integrated_then_status_is_active(
    ops_test: OpsTest,
    vault_authorized: Task,
    haproxy_idle: Task,
    self_signed_certificates_idle: Task,
):
    assert ops_test.model
    await gather(vault_authorized, haproxy_idle, self_signed_certificates_idle)

    haproxy_app = get_app(ops_test.model, HAPROXY_APPLICATION_NAME)
    external_hostname = "example.haproxy.com"
    await haproxy_app.set_config({"external-hostname": external_hostname})

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{HAPROXY_APPLICATION_NAME}:certificates",
    )

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:ingress",
        relation2=f"{HAPROXY_APPLICATION_NAME}:ingress",
    )

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
