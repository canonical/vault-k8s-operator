# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from pathlib import Path
from typing import Tuple

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    crash_pod,
)
from tests.integration.integration_support import (
    APPLICATION_NAME,
    VAULT_KV_REQUIRER_1_APPLICATION_NAME,
    VAULT_KV_REQUIRER_2_APPLICATION_NAME,
)


class TestVaultKv:
    """Exercise kv behavior."""

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
        request: pytest.FixtureRequest,
    ):
        assert ops_test.model
        kv_requirer_path = request.config.getoption("--kv_requirer_charm_path")
        if not isinstance(kv_requirer_path, str) or not kv_requirer_path:
            pytest.fail("--kv_requirer_charm_path is required for KV integration tests")
        kv_requirer_charm_path = Path(kv_requirer_path).resolve()
        deploy_vault_kv_requirer_1 = ops_test.model.deploy(
            kv_requirer_charm_path,
            application_name=VAULT_KV_REQUIRER_1_APPLICATION_NAME,
            num_units=1,
        )
        deploy_vault_kv_requirer_2 = ops_test.model.deploy(
            kv_requirer_charm_path,
            application_name=VAULT_KV_REQUIRER_2_APPLICATION_NAME,
            num_units=1,
        )
        deployed_apps = [
            VAULT_KV_REQUIRER_1_APPLICATION_NAME,
            VAULT_KV_REQUIRER_2_APPLICATION_NAME,
        ]
        await asyncio.gather(
            deploy_vault_kv_requirer_1,
            deploy_vault_kv_requirer_2,
        )
        await ops_test.model.wait_for_idle(
            apps=deployed_apps,
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        secret_key = "test-key"
        secret_value = "test-value"
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_related_and_requirer_pod_crashes_when_create_secret_then_secret_is_created(  # noqa: E501
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        secret_key = "test-key"
        secret_value = "test-value"
        assert ops_test.model
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        k8s_namespace = ops_test.model.name

        crash_pod(
            name=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}-0",
            namespace=k8s_namespace,
        )

        await ops_test.model.wait_for_idle(
            apps=[VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value

    @pytest.mark.abort_on_fail
    async def test_given_multiple_kv_requirers_related_when_secrets_created_then_secrets_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_2_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        secret_key = "test-key-2"
        secret_value = "test-value-2"
        assert ops_test.model
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_2_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value
