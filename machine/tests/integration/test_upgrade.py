# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    deploy_vault_and_wait,
    get_ca_cert_file_location,
    refresh_application,
    unseal_all_vault_units,
)
from tests.integration.integration_support import (
    CURRENT_TRACK_FIRST_STABLE_REVISION,
    CURRENT_TRACK_LATEST_STABLE_CHANNEL,
    NUM_VAULT_UNITS,
    authorize_charm,
    initialize_vault_leader,
    logger,
)


async def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest,
    vault_charm_path: Path,
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    application_name_in_model = "first"
    await deploy_vault_and_wait(
        ops_test,
        app_name_in_model=application_name_in_model,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
        status="blocked",
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, application_name_in_model)
    async with ops_test.fast_forward(fast_interval="60s"):
        await unseal_all_vault_units(
            ops_test,
            await get_ca_cert_file_location(ops_test, application_name_in_model),
            unseal_key,
            app_name=application_name_in_model,
        )
        await authorize_charm(ops_test, root_token, app_name=application_name_in_model)
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, application_name_in_model, vault_charm_path)

        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )


async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest,
    vault_charm_path: Path,
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    application_name_in_model = "latest"
    await deploy_vault_and_wait(
        ops_test,
        app_name_in_model=application_name_in_model,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        status="blocked",
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, application_name_in_model)
    async with ops_test.fast_forward(fast_interval="60s"):
        await unseal_all_vault_units(
            ops_test,
            await get_ca_cert_file_location(ops_test, application_name_in_model),
            unseal_key,
            app_name=application_name_in_model,
        )
        await authorize_charm(ops_test, root_token, app_name=application_name_in_model)
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, application_name_in_model, vault_charm_path)

        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
