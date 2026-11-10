# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from typing import Tuple

import pytest
from juju.application import Application
from pytest import FixtureRequest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    crash_pod,
    get_model_secret_field,
    revoke_token,
    wait_for_status_message,
)
from tests.integration.integration_support import (
    APPLICATION_NAME,
    AUTOUNSEAL_TOKEN_SECRET_LABEL,
    METADATA,
    authorize_charm,
    initialize_vault_leader,
    read_vault_unit_statuses,
)


class TestVaultAutounseal:
    """Test Vault as an auto-unseal provider and requirer."""

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
        request: FixtureRequest,
    ):
        assert ops_test.model
        resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
        charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
        await ops_test.model.deploy(
            charm_path,
            resources=resources,
            application_name="vault-b",
            trust=True,
            series="jammy",
            num_units=1,
            config={"common_name": "example.com"},
        )
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

        yield
        await ops_test.model.remove_application(app_name="vault-b")

    @pytest.mark.abort_on_fail
    async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        await ops_test.model.integrate(
            f"{APPLICATION_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=["vault-b"], status="blocked", wait_for_exact_units=1, idle_period=5
            )

            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please initialize Vault",
                app_name="vault-b",
            )

            leader_unit_index, root_token, recovery_key = await initialize_vault_leader(
                ops_test, "vault-b"
            )
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                app_name="vault-b",
            )
            await authorize_charm(ops_test, root_token, "vault-b")
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=1,
                idle_period=5,
            )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_scale_up_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await app.scale(1)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
            idle_period=5,
        )
        await app.scale(3)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_all_units_crash_then_units_recover(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )
        k8s_namespace = ops_test.model.name
        crash_pod(name="vault-b-0", namespace=k8s_namespace)
        crash_pod(name="vault-b-1", namespace=k8s_namespace)
        crash_pod(name="vault-b-2", namespace=k8s_namespace)
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=3,
                idle_period=5,
            )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_auth_token_goes_bad_then_units_recover(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )
        auth_token = await get_model_secret_field(
            ops_test=ops_test, label=AUTOUNSEAL_TOKEN_SECRET_LABEL, field="token"
        )
        leader_unit_index, root_token, _ = active_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        revoke_token(
            token_to_revoke=auth_token,
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
        )
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=3,
                idle_period=5,
            )
