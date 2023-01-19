#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from pathlib import Path
from typing import Tuple

import pytest
import requests.exceptions  # type: ignore[import]
import yaml
from juju.errors import JujuError

from tests.integration.kubernetes import Kubernetes
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"


class TestVaultK8s:
    @pytest.fixture(scope="module")
    @pytest.mark.abort_on_fail
    async def charm(self, ops_test):
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        return charm

    @pytest.fixture()
    async def cleanup(self, ops_test):
        try:
            await ops_test.model.remove_application(
                app_name=APPLICATION_NAME, block_until_done=True
            )
        except JujuError:
            pass

    @staticmethod
    async def wait_for_load_balancer_address(kubernetes: Kubernetes, timeout: float = 60):
        initial_time = time.time()
        while time.time() - initial_time < timeout:
            load_balancer_address = kubernetes.get_load_balancer_address(
                service_name=APPLICATION_NAME
            )
            if load_balancer_address:
                return load_balancer_address
            time.sleep(5)
        raise TimeoutError("Timed out waiting for Loadbalancer address to be available.")

    @staticmethod
    async def initialize_vault(vault: Vault, timeout: int = 60) -> Tuple[str, str]:
        """Initializes Vault.

        Args:
            vault: Vault object.
            timeout: Timeout (seconds)

        Returns:
            str: Vault's Unseal key
            str: Vault's Root token
        """
        initial_time = time.time()
        while time.time() - initial_time < timeout:
            try:
                unseal_key, root_token = vault.initialize()
                return unseal_key, root_token
            except requests.exceptions.ConnectTimeout:
                logger.info("Vault not yet ready - Waiting")
        raise TimeoutError("Timed out waiting for Vault to be ready.")

    @staticmethod
    async def deploy_charm(ops_test, charm: Path) -> None:
        """Deploys charm.

        Args:
            ops_test:
            charm: Charm path.

        Returns:
            None
        """
        resources = {
            "vault-image": METADATA["resources"]["vault-image"]["upstream-source"],
        }
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
        )

    async def post_deployment_tasks(self, namespace: str) -> str:
        """Runs post deployment tasks as explained in the README.md.

        Retrieves Vault's LoadBalancer address, initializes Vault and generates a token for
        the charm.

        Args:
            namespace (str): Kubernetes namespace

        Returns:
            str: Generated token.
        """
        kubernetes = Kubernetes(namespace=namespace)
        load_balancer_address = await self.wait_for_load_balancer_address(kubernetes=kubernetes)
        vault = Vault(url=f"http://{load_balancer_address}:8200")
        unseal_key, root_token = await self.initialize_vault(vault=vault)
        vault.set_token(root_token)
        vault.unseal(unseal_key=unseal_key)
        generated_token = vault.generate_token(ttl="5m")
        return generated_token

    async def test_given_no_config_when_deploy_then_status_is_waiting(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        await self.deploy_charm(ops_test, charm)

        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

    async def test_given_no_config_when_post_deployment_tasks_and_authorise_charm_then_status_is_active(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        """This test follows the README.MD deployment and post-deployment tasks.

        Args:
            ops_test: Ops test Framework
            charm: Charm path

        Returns:
            None
        """
        await self.deploy_charm(ops_test, charm)
        vault_unit = ops_test.model.units["vault-k8s/0"]
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

        vault_token = await self.post_deployment_tasks(namespace=ops_test.model_name)

        await vault_unit.run_action(action_name="authorise-charm", token=vault_token)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

    async def test_given_status_is_active_when_run_issue_certificate_action_then_certificates_are_issued(  # noqa: E501
        self, ops_test, charm, cleanup
    ):
        """This test runs the "generate-certificate" Juju action.

        Args:
            ops_test: Ops test Framework
            charm: Charm path

        Returns:
            None
        """
        await self.deploy_charm(ops_test, charm)
        vault_unit = ops_test.model.units["vault-k8s/0"]
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=1000)

        vault_token = await self.post_deployment_tasks(namespace=ops_test.model_name)

        await vault_unit.run_action(action_name="authorise-charm", token=vault_token)
        await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=1000)

        action = await vault_unit.run_action(
            action_name="generate-certificate", cn="whatever", sans=""
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id, wait=60
        )
        assert action_output["return-code"] == 0
        assert "ca-chain" in action_output and action_output["ca-chain"] is not None
        assert "issuing-ca" in action_output and action_output["issuing-ca"] is not None
        assert "certificate" in action_output and action_output["certificate"] is not None
        assert "private-key" in action_output and action_output["private-key"] is not None
