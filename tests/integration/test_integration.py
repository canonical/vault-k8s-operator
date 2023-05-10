#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time
from pathlib import Path
from typing import Optional, Tuple

import pytest
import requests.exceptions
import yaml
from pytest_operator.plugin import OpsTest

from tests.integration.kubernetes import Kubernetes
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"


class TestVaultK8s:
    @staticmethod
    async def wait_for_load_balancer_address(
        kubernetes: Kubernetes, timeout: int = 60
    ) -> Optional[str]:
        """Waits for LoadBalancer address to be available and returns it.

        Args:
            kubernetes: Kubernetes object.
            timeout: Timeout (seconds).

        Returns:
            str: LoadBalancer address.

        Raises:
            TimeoutError: If LoadBalancer address is not available after timeout.
        """
        initial_time = time.time()
        while time.time() - initial_time < timeout:
            if load_balancer_address := kubernetes.get_load_balancer_address(
                service_name=APPLICATION_NAME
            ):
                return load_balancer_address
            time.sleep(5)
        raise TimeoutError("Timed out waiting for Loadbalancer address to be available.")

    @staticmethod
    async def initialize_vault(vault: Vault, timeout: int = 60) -> Optional[Tuple[str, str]]:
        """Initializes Vault.

        Args:
            vault: Vault object.
            timeout: Timeout (seconds).

        Returns:
            str: Vault's Unseal key.
            str: Vault's Root token.

        Raises:
            TimeoutError: If Vault is not ready after timeout.
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

    async def post_deployment_tasks(self, ops_test: OpsTest) -> str:
        """Runs post deployment tasks as explained in the README.md.

        Retrieves Vault's LoadBalancer address, initializes Vault and generates a token for
        the charm.

        Args:
            ops_test: Ops test Framework.

        Returns:
            str: Generated token.
        """
        kubernetes = Kubernetes(namespace=ops_test.model_name)  # type: ignore[arg-type]
        load_balancer_address = await self.wait_for_load_balancer_address(kubernetes=kubernetes)
        vault = Vault(url=f"http://{load_balancer_address}:8200")
        unseal_key, root_token = await self.initialize_vault(vault=vault)  # type: ignore[misc]
        vault.set_token(root_token)
        vault.unseal(unseal_key=unseal_key)
        generated_token = vault.generate_token(ttl="5m")
        return generated_token

    @pytest.mark.abort_on_fail
    async def test_given_no_config_when_deploy_then_status_is_blocked(  # noqa: E501
        self, ops_test: OpsTest, build_and_deploy
    ):
        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME], status="blocked", timeout=1000
        )

    @pytest.mark.abort_on_fail
    async def test_given_no_config_when_post_deployment_tasks_and_authorise_charm_then_status_is_active(  # noqa: E501
        self, ops_test: OpsTest, build_and_deploy
    ):
        """This test follows the README.md deployment and post-deployment tasks.

        Args:
            ops_test: Ops test Framework.
            build_and_deploy: Pytest fixture.
        """
        vault_unit = ops_test.model.units["vault-k8s/0"]  # type: ignore[union-attr]

        vault_token = await self.post_deployment_tasks(ops_test)
        await vault_unit.run_action(action_name="authorise-charm", token=vault_token)

        await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
            apps=[APPLICATION_NAME], status="active", timeout=1000
        )
