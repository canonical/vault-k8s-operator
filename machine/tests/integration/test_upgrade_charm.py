import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

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

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_first_stable_revision_when_refresh_then_status_is_active(
    ops_test: OpsTest, vault_charm_path: Path
):
    assert ops_test.model
    # TODO change this to stable once there is a release
    # Replace channel with revision
    # First Stable revision
    # Last stable revision is channel 1.18/stable
    await deploy_vault_and_wait(ops_test, NUM_VAULT_UNITS, status="blocked", channel="1.18/edge")
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
