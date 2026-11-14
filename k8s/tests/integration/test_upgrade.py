# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

from pytest import FixtureRequest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    refresh_application,
    wait_for_status_message,
)
from tests.integration.integration_support import (
    APPLICATION_NAME,
    CURRENT_TRACK_FIRST_STABLE_REVISION,
    CURRENT_TRACK_LATEST_STABLE_CHANNEL,
    NUM_VAULT_UNITS,
    authorize_charm,
    initialize_vault_leader,
    logger,
    read_vault_unit_statuses,
    unseal_all_vaults,
    unseal_vault,
)


class TestUpgradeVaultFirstStableRevision:
    """Test the upgrade from the first stable revision within track to current build."""

    async def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
        self, ops_test: OpsTest, request: FixtureRequest
    ):
        assert ops_test.model
        logger.info("Deploying vault from Charmhub")
        application_name_in_model = "first"
        await ops_test.model.deploy(
            APPLICATION_NAME,
            application_name=application_name_in_model,
            channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
            revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
            num_units=NUM_VAULT_UNITS,
        )
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        leader_unit_index, root_token, unseal_key = await initialize_vault_leader(
            ops_test, application_name_in_model
        )
        unit_addresses = [
            row["address"]
            for row in await read_vault_unit_statuses(ops_test, application_name_in_model)
        ]
        async with ops_test.fast_forward(fast_interval="60s"):
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                app_name=application_name_in_model,
            )
            unseal_all_vaults(unit_addresses, root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                unit_name=f"{application_name_in_model}/{leader_unit_index}",
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
            vault_charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
            await refresh_application(ops_test, application_name_in_model, vault_charm_path)
            await ops_test.model.wait_for_idle(
                apps=[application_name_in_model],
                status="blocked",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )
            unit_addresses = [
                row["address"]
                for row in await read_vault_unit_statuses(ops_test, application_name_in_model)
            ]
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            unseal_all_vaults(unit_addresses, root_token, unseal_key)
            await ops_test.model.wait_for_idle(
                apps=[application_name_in_model],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )


class TestUpgradeVaultLatestStableRevision:
    """Test the upgrade from the latest stable revision within track to current build."""

    async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
        self, ops_test: OpsTest, request: FixtureRequest
    ):
        assert ops_test.model
        logger.info("Deploying vault from Charmhub")
        application_name_in_model = "latest"
        await ops_test.model.deploy(
            APPLICATION_NAME,
            application_name=application_name_in_model,
            channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
            num_units=NUM_VAULT_UNITS,
        )
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        leader_unit_index, root_token, unseal_key = await initialize_vault_leader(
            ops_test, application_name_in_model
        )
        unit_addresses = [
            row["address"]
            for row in await read_vault_unit_statuses(ops_test, application_name_in_model)
        ]
        async with ops_test.fast_forward(fast_interval="60s"):
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                app_name=application_name_in_model,
            )
            unseal_all_vaults(unit_addresses, root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                app_name=application_name_in_model,
                unit_name=f"{application_name_in_model}/{leader_unit_index}",
            )
            await authorize_charm(ops_test, root_token, app_name=application_name_in_model)
            await ops_test.model.wait_for_idle(
                apps=[application_name_in_model],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )

            logger.info("Refreshing vault from built charm")
            vault_charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
            await refresh_application(ops_test, application_name_in_model, vault_charm_path)
            await ops_test.model.wait_for_idle(
                apps=[application_name_in_model],
                status="blocked",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )
            unit_addresses = [
                row["address"]
                for row in await read_vault_unit_statuses(ops_test, application_name_in_model)
            ]
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            unseal_all_vaults(unit_addresses, root_token, unseal_key)
            await ops_test.model.wait_for_idle(
                apps=[application_name_in_model],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )
