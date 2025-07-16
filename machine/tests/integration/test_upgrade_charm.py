import logging
from pathlib import Path

import pytest
from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
)
from helpers import (
    authorize_charm,
    deploy_vault_and_wait,
    get_ca_cert_file_location,
    initialize_vault_leader,
    refresh_application,
    unseal_all_vault_units,
)
from juju.errors import JujuError
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.17/stable"
CURRENT_TRACK_FIRST_STABLE_REVISION = 442


@pytest.mark.abort_on_fail
async def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
    await deploy_vault_and_wait(
        ops_test,
        NUM_VAULT_UNITS,
        status="blocked",
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, APP_NAME)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, await get_ca_cert_file_location(ops_test)
        )

        await authorize_charm(ops_test, root_token)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    await refresh_application(ops_test, APP_NAME, vault_charm_path)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, await get_ca_cert_file_location(ops_test)
        )

        await authorize_charm(ops_test, root_token)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    await ops_test.model.remove_application(APP_NAME)


@pytest.mark.abort_on_fail
async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    await deploy_vault_and_wait(
        ops_test, NUM_VAULT_UNITS, status="blocked", channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, APP_NAME)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, await get_ca_cert_file_location(ops_test)
        )

        await authorize_charm(ops_test, root_token)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    await refresh_application(ops_test, APP_NAME, vault_charm_path)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, await get_ca_cert_file_location(ops_test)
        )

        await authorize_charm(ops_test, root_token)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )
