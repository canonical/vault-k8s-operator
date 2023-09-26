#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import time
from pathlib import Path

import hvac  # type: ignore[import]
import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEFIK_APPLICATION_NAME = "traefik"
EXTERNAL_HOSTNAME = "mydomain.com"

class InvalidHostError(Exception):
    pass


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

    async def _get_vault_endpoint(self, ops_test: OpsTest) -> str:
        """Retrieves the Vault endpoint by using Traefik's `show-proxied-endpoints` action.

        Args:
            ops_test: Ops test Framework.

        Returns:
            vault_endpoint: Vault proxied endpoint by Traefik.

        Raises:
            TimeoutError: If proxied endpoints are not retrieved.
        """
        traefik = ops_test.model.applications[TRAEFIK_APP_NAME]  # type: ignore[union-attr]
        traefik_unit = traefik.units[0]
        t0 = time.time()
        timeout = 120  # seconds
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

    def _get_url(self, vault_endpoint: str) -> str:
        """Returns the URL formatted as https://<host>/<path> from the vault endpoint.

        Args:
            vault_endpoint:  Vault proxied endpoint by Traefik.

        Returns:
            url: URL formatted as https://<host>/<path>

        Raises:
            InvalidHostException: If vault host address is empty
        """
        host, path = "", ""
        uri = vault_endpoint.split("//")[1]
        host = uri.split(":")[0]
        if not host:
            raise InvalidHostError("Vault host address is invalid.")
        if len(uri.split(":")) == 2 and len(uri.split(":")[1].split("/")) == 2:
            path = uri.split(":")[1].split("/")[1]
        return f"https://{host}/{path}"

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
            config={"external_hostname": EXTERNAL_HOSTNAME, "routing_mode": "subdomain"},
            trust=True,
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

    async def test_given_traefik_is_deployed_and_related_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_traefik,
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
    async def test_given_related_to_traefik_when_vault_status_checked_then_returns_400(
        self, ops_test: OpsTest
    ):
        """Sending a request without token and returns 400 Bad Request.

        This proves that vault is reachable behind ingress.
        Juju secrets belongs to model are not gathered using pytest-operator,
        so vault token is missing in the request causes authorization problems.
        """
        vault_endpoint = await self._get_vault_endpoint(ops_test)
        url = self._get_url(vault_endpoint)
        self._client = hvac.Client(url=url, verify=False)
        response = self._client.sys.read_health_status()
        assert str(response) == "<Response [400]>"
