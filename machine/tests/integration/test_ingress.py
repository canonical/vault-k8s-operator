from asyncio import Task

from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    HAPROXY_APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
)


async def test_given_haproxy_deployed_when_integrated_then_status_is_active(
    ops_test: OpsTest,
    haproxy_idle: Task,
    self_signed_certificates_idle: Task,
    vault_authorized: Task,
):
    assert ops_test.model
    await haproxy_idle
    await self_signed_certificates_idle
    await vault_authorized

    haproxy_app = ops_test.model.applications[HAPROXY_APPLICATION_NAME]
    external_hostname = "haproxy"
    await haproxy_app.set_config({"external-hostname": external_hostname})

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{HAPROXY_APPLICATION_NAME}:certificates",
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:ingress",
        relation2=f"{HAPROXY_APPLICATION_NAME}:ingress",
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )
