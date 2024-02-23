#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import os
import shutil
import time
from os.path import abspath
from pathlib import Path

import hvac  # type: ignore[import-untyped]
import pytest
import yaml
from juju.application import Application
from juju.unit import Unit
from lightkube import Client as KubernetesClient
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import crash_pod

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEFIK_APPLICATION_NAME = "traefik"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

NUM_VAULT_UNITS = 5

k8s = KubernetesClient()


def copy_lib_content() -> None:
    shutil.copyfile(src=VAULT_KV_LIB_DIR, dst=f"{VAULT_KV_REQUIRER_CHARM_DIR}/{VAULT_KV_LIB_DIR}")


class TestVaultK8s:
    @staticmethod
    async def deploy_charm(ops_test: OpsTest, charm: Path) -> None:
        """Deploys charm.

        Args:
            ops_test: Ops test Framework.
            charm: Charm path.
        """
        assert ops_test.model
        resources = {
            "vault-image": METADATA["resources"]["vault-image"]["upstream-source"],
        }
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
            series="jammy",
            num_units=NUM_VAULT_UNITS,
        )

    async def _get_vault_endpoint(self, ops_test: OpsTest, timeout: int = 60) -> str:
        """Retrieve the Vault endpoint by using Traefik's `show-proxied-endpoints` action.

        Args:
            ops_test: Ops test Framework.
            timeout: Wait time in seconds to get proxied endpoints.

        Returns:
            vault_endpoint: Vault proxied endpoint by Traefik.

        Raises:
            TimeoutError: If proxied endpoints are not retrieved.

        """
        assert ops_test.model
        traefik = ops_test.model.applications[TRAEFIK_APPLICATION_NAME]
        assert isinstance(traefik, Application)
        traefik_unit = traefik.units[0]
        t0 = time.time()
        while time.time() - t0 < timeout:
            proxied_endpoint_action = await traefik_unit.run_action(
                action_name="show-proxied-endpoints"
            )
            action_output = await ops_test.model.get_action_output(
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
        """Run the `get-certificate` on the `vault-k8s` unit.

        Args:
            ops_test (OpsTest): OpsTest
            timeout (int, optional): Timeout in seconds. Defaults to 60.

        Returns:
            dict: Action output
        """
        assert ops_test.model
        self_signed_certificates_unit = ops_test.model.units[
            f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0"
        ]
        assert isinstance(self_signed_certificates_unit, Unit)
        action = await self_signed_certificates_unit.run_action(
            action_name="get-ca-certificate",
        )
        return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_prometheus(self, ops_test: OpsTest) -> None:
        """Deploy Prometheus.

        Args:
            ops_test: Ops test Framework.
        """
        assert ops_test.model
        await ops_test.model.deploy(
            "prometheus-k8s",
            application_name=PROMETHEUS_APPLICATION_NAME,
            trust=True,
        )

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def build_and_deploy(self, ops_test: OpsTest):
        """Build and deploys vault-k8s charm.

        Args:
            ops_test: Ops test Framework.
        """
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        assert charm is not None
        await self.deploy_charm(ops_test, charm)

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_traefik(self, ops_test: OpsTest):
        """Deploy Traefik.

        Args:
            ops_test: Ops test Framework.
        """
        assert ops_test.model
        await ops_test.model.deploy(
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
        assert ops_test.model
        await ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            trust=True,
            channel="beta",
        )

    @pytest.mark.abort_on_fail
    async def test_given_default_config_when_deploy_then_status_is_active(
        self, ops_test: OpsTest, build_and_deploy
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
        build_and_deploy,
    ):
        assert ops_test.model
        unit = ops_test.model.units[f"{APPLICATION_NAME}/1"]
        assert isinstance(unit, Unit)
        k8s_namespace = ops_test.model.name
        crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

    async def test_given_traefik_is_deployed_when_related_to_self_signed_certificates_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_traefik,
        deploy_self_signed_certificates_operator,
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{TRAEFIK_APPLICATION_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_traefik_is_deployed_when_certificate_transfer_interface_is_related_then_status_is_active(
        self, ops_test: OpsTest
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:send-ca-cert",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:receive-ca-cert",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_certificate_transfer_interface_is_related_when_relate_to_ingress_then_status_is_active(
        self, ops_test: OpsTest
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:ingress",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:ingress",
        )
        await ops_test.model.wait_for_idle(
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
        client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
        response = client.sys.read_health_status()
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
        assert response.status_code in (200, 429)
        os.remove("ca_file.txt")

    async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
        self, ops_test: OpsTest
    ):
        copy_lib_content()
        vault_kv_requirer_path = await ops_test.build_charm(f"{VAULT_KV_REQUIRER_CHARM_DIR}/")
        assert ops_test.model
        await ops_test.model.deploy(
            vault_kv_requirer_path,
            application_name=VAULT_KV_REQUIRER_APPLICATION_NAME,
            num_units=1,
        )
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
        self, ops_test
    ):
        secret_key = "test-key"
        secret_value = "test-value"
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_APPLICATION_NAME]
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
    async def test_given_vault_deployed_when_tls_access_relation_created_then_existing_certificate_replaced(
        self, ops_test: OpsTest
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results["stdout"]

        await ops_test.model.integrate(
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{APPLICATION_NAME}:tls-certificates-access",
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        final_ca_cert = action.results["stdout"]
        assert initial_ca_cert != final_ca_cert

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_destroyed_then_self_signed_cert_created(
        self, ops_test
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results

        await ops_test.model.applications[APPLICATION_NAME].remove_relation(
            "tls-certificates-access", f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates"
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        final_ca_cert = action.results
        assert initial_ca_cert != final_ca_cert

    @pytest.mark.abort_on_fail
    async def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
        self, ops_test: OpsTest, build_and_deploy, deploy_prometheus
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
    async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
        self,
        ops_test: OpsTest,
        build_and_deploy,
    ):
        assert ops_test.model
        num_units = 7
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.scale(num_units)

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
        build_and_deploy,
    ):
        assert ops_test.model
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.scale(NUM_VAULT_UNITS)

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

    @pytest.mark.abort_on_fail
    async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
        self, ops_test: OpsTest
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:tls-certificates-pki",
            relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
