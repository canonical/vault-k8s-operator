#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import os
import time
from os.path import abspath
from pathlib import Path

import hvac  # type: ignore[import-untyped]
import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEFIK_APPLICATION_NAME = "traefik"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"


class TestVaultK8s:
    @staticmethod
    async def deploy_charm(ops_test: OpsTest, charm: Path) -> None:
        """Deploys charm.

        Args:
            ops_test: Ops test Framework.
            charm: Charm path.
        """
        resources = {
            "vault-image": METADATA["resources"]["vault-image"]["upstream-source"],
        }
        await ops_test.model.deploy(  # type: ignore[union-attr]
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
            series="jammy",
            num_units=5,
        )

    async def _get_vault_endpoint(self, ops_test: OpsTest, timeout: int = 60) -> str:
        """Retrieves the Vault endpoint by using Traefik's `show-proxied-endpoints` action.

        Args:
            ops_test: Ops test Framework.
            timeout: Wait time in seconds to get proxied endpoints.

        Returns:
            vault_endpoint: Vault proxied endpoint by Traefik.

        Raises:
            TimeoutError: If proxied endpoints are not retrieved.

        """
        traefik = ops_test.model.applications[TRAEFIK_APPLICATION_NAME]  # type: ignore[union-attr]
        traefik_unit = traefik.units[0]
        t0 = time.time()
        while time.time() - t0 < timeout:
            proxied_endpoint_action = await traefik_unit.run_action(
                action_name="show-proxied-endpoints"
            )
            action_output = await ops_test.model.get_action_output(  # type: ignore[union-attr]
                action_uuid=proxied_endpoint_action.entity_id, wait=30
            )

            if "proxied-endpoints" in action_output:
                proxied_endpoints = json.loads(action_output["proxied-endpoints"])
                return proxied_endpoints[APPLICATION_NAME]["url"]
            else:
                logger.info("Traefik did not return proxied endpoints yet")
            time.sleep(2)

        raise TimeoutError("Traefik did not return proxied endpoints")

    async def run_get_ca_certificate_action(self, ops_test: OpsTest, timeout: int = 60) -> dict:
        """Runs `get-certificate` on the `vault-k8s` unit.

        Args:
            ops_test (OpsTest): OpsTest

        Returns:
            dict: Action output
        """
        self_signed_certificates_unit = ops_test.model.units[  # type: ignore[union-attr]
            f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0"
        ]
        action = await self_signed_certificates_unit.run_action(
            action_name="get-ca-certificate",
        )
        return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)  # type: ignore[union-attr]

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_prometheus(self, ops_test: OpsTest) -> None:
        """Deploys Prometheus.

        Args:
            ops_test: Ops test Framework.
        """
        await ops_test.model.deploy(  # type: ignore[union-attr]
            "prometheus-k8s",
            application_name=PROMETHEUS_APPLICATION_NAME,
            trust=True,
        )

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def build_and_deploy(self, ops_test: OpsTest):
        """Builds and deploys vault-k8s charm.

        Args:
            ops_test: Ops test Framework.
        """
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        await self.deploy_charm(ops_test, charm)

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_traefik(self, ops_test: OpsTest):
        """Deploy Traefik.

        Args:
            ops_test: Ops test Framework.
        """
        await ops_test.model.deploy(  # type: ignore[union-attr]
            "traefik-k8s",
            application_name=TRAEFIK_APPLICATION_NAME,
            trust=True,
            channel="edge",
        )

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_self_signed_certificates_operator(self, ops_test: OpsTest):
        """Deploy Self Signed Certificates Operator.

        Args:
            ops_test: Ops test Framework.
        """
        await ops_test.model.deploy(  # type: ignore[union-attr]
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            trust=True,
            channel="beta",
        )

    @pytest.mark.abort_on_fail
    async def test_given_default_config_when_deploy_then_status_is_active(
        self, ops_test: OpsTest, build_and_deploy
    ):
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=5,
        )

    async def test_given_traefik_is_deployed_when_related_to_self_signed_certificates_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_traefik,
        deploy_self_signed_certificates_operator,
    ):
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{TRAEFIK_APPLICATION_NAME}",
        )
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_traefik_is_deployed_when_certificate_transfer_interface_is_related_then_status_is_active(
        self, ops_test: OpsTest
    ):
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:send-ca-cert",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:receive-ca-cert",
        )
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME, TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_certificate_transfer_interface_is_related_when_relate_to_ingress_then_status_is_active(
        self, ops_test: OpsTest
    ):
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:ingress",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:ingress",
        )
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME, TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_given_traefik_is_related_when_vault_status_checked_then_vault_returns_200_or_429(
        self,
        ops_test: OpsTest,
    ):
        """This proves that vault is reachable behind ingress."""
        vault_endpoint = await self._get_vault_endpoint(ops_test)
        action_output = await self.run_get_ca_certificate_action(ops_test)
        ca_certificate = action_output["ca-certificate"]
        with open("ca_file.txt", mode="w+") as ca_file:
            ca_file.write(ca_certificate)
        self._client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
        response = self._client.sys.read_health_status()
        # As we have multiple Vault units, the one who gives the response could be in active or standby.  # noqa: E501, W505
        # According to the Vault upstream code, expected response codes could be "200"
        # if the unit is active or "429" if the unit is standby.
        # https://github.com/hashicorp/vault/blob/3c42b15260de8b94388ed2296fc18e89ea80c4c9/vault/logical_system_paths.go#L152  # noqa: E501, W505
        # Summary: "Returns the health status of Vault.",
        # 200: {{Description: "initialized, unsealed, and active"}}
        # 429: {{Description: "unsealed and standby"}}
        # 472: {{Description: "data recovery mode replication secondary and active"}}
        # 501: {{Description: "not initialized"}}
        # 503: {{Description: "sealed"}}
        assert str(response) == "<Response [200]>" or "<Response [429]>"
        os.remove("ca_file.txt")

    @pytest.mark.abort_on_fail
    async def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
        self, ops_test: OpsTest, build_and_deploy, deploy_prometheus
    ):
        await ops_test.model.add_relation(  # type: ignore[union-attr]
            relation1=f"{APPLICATION_NAME}:metrics-endpoint",
            relation2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
        )
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME, APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
    ):
        num_units = 7
        await ops_test.model.applications[APPLICATION_NAME].scale(num_units)  # type: ignore[union-attr]  # noqa: E501

        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=num_units,
        )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
    ):
        num_units = 3
        await ops_test.model.applications[APPLICATION_NAME].scale(num_units)  # type: ignore[union-attr]  # noqa: E501

        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=num_units,
        )
