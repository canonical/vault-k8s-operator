import asyncio
import logging
from asyncio import Task

import pytest
import requests
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.constants import (
    APP_NAME,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    UNMATCHING_COMMON_NAME,
)
from tests.integration.helpers import get_app, get_leader, has_relation

logger = logging.getLogger(__name__)


async def verify_acme_configured(ops_test: OpsTest, app_name: str) -> bool:
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    url = f"https://{leader_ip}:8200/v1/charm-acme/acme/directory"

    retry_count = 12
    for attempt in range(retry_count):
        try:
            response = requests.get(url, verify=False)
            if response.status_code == 200 and "newNonce" in response.json():
                return True
        except (requests.RequestException, ValueError) as e:
            logger.warning("ACME check attempt %s/%s failed: %s", attempt + 1, retry_count, str(e))

        if attempt < retry_count - 1:
            await asyncio.sleep(5)

    return False


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_tls_certificates_acme_relation_when_integrate_then_status_is_active_and_acme_configured(
    ops_test: OpsTest, vault_authorized: Task, self_signed_certificates_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await self_signed_certificates_idle

    vault_app = get_app(ops_test.model)
    common_name = UNMATCHING_COMMON_NAME
    common_name_config = {
        "common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
    if not has_relation(vault_app, "tls-certificates-acme"):
        await ops_test.model.integrate(
            relation1=f"{APP_NAME}:tls-certificates-acme",
            relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.wait_for_idle(
        apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
        status="active",
    )
    assert await verify_acme_configured(ops_test, APP_NAME)
