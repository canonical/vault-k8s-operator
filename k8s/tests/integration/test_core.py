# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Tuple

import hvac
import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    crash_pod,
    wait_for_status_message,
)
from tests.integration.integration_support import (
    APPLICATION_NAME,
    NUM_VAULT_UNITS,
    read_vault_unit_statuses,
    unseal_vault,
)


class TestVaultK8s:
    """This test class tests vault's deployment and activation."""

    @pytest.mark.smoke
    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_and_initialized_when_unsealed_and_authorized_then_status_is_active(
        self, ops_test: OpsTest, active_vault: Tuple[int, str, str]
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_pod_crashes_then_unit_recovers(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = active_vault
        crashing_pod_index = 1
        k8s_namespace = ops_test.model.name
        crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
        await wait_for_status_message(
            ops_test, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[crashing_pod_index], root_token, unseal_key)
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = active_vault
        num_units = NUM_VAULT_UNITS + 1
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.scale(num_units)

        await wait_for_status_message(
            ops_test, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[-1], root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
                wait_for_exact_units=num_units,
            )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, _ = active_vault
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)

        unit_addresses = [row.get("address") for row in await read_vault_unit_statuses(ops_test)]
        client = hvac.Client(url=f"https://{unit_addresses[-1]}:8200", verify=False)
        client.token = root_token
        response = client.sys.read_raft_config()
        assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS + 1

        await app.scale(NUM_VAULT_UNITS)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        unit_addresses = [row.get("address") for row in await read_vault_unit_statuses(ops_test)]
        client = hvac.Client(url=f"https://{unit_addresses[0]}:8200", verify=False)
        client.token = root_token
        response = client.sys.read_raft_config()
        assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS
