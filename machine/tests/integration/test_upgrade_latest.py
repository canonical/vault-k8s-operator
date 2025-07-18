import logging
from pathlib import Path

import pytest
from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
)
from helpers import (
    deploy_vault_and_wait,
    refresh_application,
    initialize_unseal_authorize_vault,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.17/stable"


@pytest.mark.abort_on_fail
async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    await deploy_vault_and_wait(
        ops_test, NUM_VAULT_UNITS, status="blocked", channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL
    )
    await initialize_unseal_authorize_vault(ops_test, APP_NAME)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, APP_NAME, vault_charm_path)

    # In the case of machine the service is not restarted on refresh, so Vault doesn't get sealed.
    logger.info("Waiting for vault to be active after refresh")

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )
