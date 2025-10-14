import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    REFRESH_TIMEOUT,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault_and_wait,
    initialize_unseal_authorize_vault,
    refresh_application,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.18/stable"
CURRENT_TRACK_FIRST_STABLE_REVISION = 546


@pytest.mark.abort_on_fail
async def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    await deploy_vault_and_wait(
        ops_test,
        NUM_VAULT_UNITS,
        status="blocked",
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
    )
    _, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
            timeout=SHORT_TIMEOUT,
        )
        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, APP_NAME, vault_charm_path)

    logger.info("Waiting for vault to be blocked after refresh")
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="blocked",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=REFRESH_TIMEOUT,
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key)

        logger.info("Waiting for vault to be active after refresh")
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
            timeout=SHORT_TIMEOUT,
        )
