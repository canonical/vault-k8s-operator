import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    LONG_TIMEOUT,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    get_ca_cert_file_location,
    initialize_unseal_authorize_vault,
    refresh_application,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.18/stable"


@pytest.mark.abort_on_fail
async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    await deploy_vault(
        ops_test=ops_test,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        charm_path=vault_charm_path,
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=SHORT_TIMEOUT,
    )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=SHORT_TIMEOUT,
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, APPLICATION_NAME, vault_charm_path)

    logger.info("Waiting for vault to be blocked after refresh")
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=LONG_TIMEOUT,
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, root_token, await get_ca_cert_file_location(ops_test)
        )

    logger.info("Waiting for vault to be active after refresh")
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=LONG_TIMEOUT,
    )
