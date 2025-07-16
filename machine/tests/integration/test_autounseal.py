import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
)
from helpers import (
    ActionFailedError,
    authorize_charm,
    deploy_vault,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    initialize_vault_leader,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APP_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    ops_test: OpsTest, deploy: VaultInit, vault_charm_path: Path
):
    # Arrange
    assert ops_test.model
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.deploy(
            vault_charm_path,
            application_name="vault-b",
            trust=True,
            num_units=1,
        )
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
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
    ops_test: OpsTest,
):
    assert ops_test.model

    app = ops_test.model.applications["vault-b"]
    assert isinstance(app, Application)
    assert len(app.units) == 1
    await app.add_units(1)
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=2,
        )
