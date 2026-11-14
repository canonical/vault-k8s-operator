# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from typing import Tuple

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.integration_support import (
    APPLICATION_NAME,
    LOKI_APPLICATION_NAME,
    PROMETHEUS_APPLICATION_NAME,
)


class TestVaultCos:
    """Exercise cos behavior."""

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        deploy_prometheus = ops_test.model.deploy(
            "prometheus-k8s",
            application_name=PROMETHEUS_APPLICATION_NAME,
            trust=True,
            channel="1/stable",
        )
        deploy_loki = ops_test.model.deploy(
            "loki-k8s",
            application_name=LOKI_APPLICATION_NAME,
            trust=True,
            channel="1/stable",
        )
        await asyncio.gather(
            deploy_prometheus,
            deploy_loki,
        )
        deployed_apps = [
            PROMETHEUS_APPLICATION_NAME,
            LOKI_APPLICATION_NAME,
        ]
        await ops_test.model.wait_for_idle(
            apps=deployed_apps,
            status="active",
            timeout=600,
            wait_for_at_least_units=1,
        )

        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:metrics-endpoint",
            relation2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_loki_deployed_when_relate_vault_to_loki_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:logging",
            relation2=f"{LOKI_APPLICATION_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, LOKI_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
