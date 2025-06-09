import logging
from asyncio import Task
from pathlib import Path

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.constants import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
)
from tests.integration.helpers import (
    ActionFailedError,
    authorize_charm,
    initialize_vault_leader,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    ops_test: OpsTest,
    vault_authorized: Task,
    self_signed_certificates_idle: Task,
    vault_charm_path: Path,
):
    # Arrange
    assert ops_test.model
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await vault_authorized
        await self_signed_certificates_idle

        await ops_test.model.deploy(
            vault_charm_path,
            application_name="vault-b",
            trust=True,
            num_units=1,
        )
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

    await ops_test.model.integrate(
        relation1="vault-b:tls-certificates-access",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )

    # Act
    await ops_test.model.integrate(
        f"{APP_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
    )
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"], status="blocked", wait_for_exact_units=1, idle_period=5
        )

        await wait_for_status_message(
            ops_test=ops_test,
            count=1,
            expected_message="Please initialize Vault",
            app_name="vault-b",
        )

        root_token, recovery_key = await initialize_vault_leader(ops_test, "vault-b")
        await wait_for_status_message(
            ops_test=ops_test,
            count=1,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            app_name="vault-b",
        )
        try:
            await authorize_charm(ops_test, root_token, "vault-b")
        except ActionFailedError:
            logger.warning("Failed to authorize charm")

    # Assert
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
            idle_period=5,
        )


@pytest.mark.abort_on_fail
async def test_given_vault_b_is_deployed_and_autounsealed_when_add_unit_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task
):
    assert ops_test.model
    await vault_authorized

    app = ops_test.model.applications["vault-b"]
    assert isinstance(app, Application)
    assert len(app.units) == 1
    await app.add_units(1)
    await ops_test.model.wait_for_idle(
        apps=["vault-b"],
        status="active",
        wait_for_exact_units=2,
        idle_period=5,
    )
