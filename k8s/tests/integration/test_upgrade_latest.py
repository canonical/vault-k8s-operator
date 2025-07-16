import logging
from pathlib import Path

import pytest
from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
)
from helpers import (
    authorize_charm,
    deploy_vault,
    get_ca_cert_file_location,
    initialize_vault_leader,
    refresh_application,
    unseal_all_vault_units,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.17/stable"


@pytest.mark.abort_on_fail
async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
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
        timeout=1000,
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, APPLICATION_NAME)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, root_token, await get_ca_cert_file_location(ops_test)
        )

    await authorize_charm(ops_test, root_token)

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )

    await refresh_application(ops_test, APPLICATION_NAME, vault_charm_path)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(
            ops_test, unseal_key, root_token, await get_ca_cert_file_location(ops_test)
        )

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
        timeout=1000,
    )
