#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains all the specificities to communicate with Vault through its API."""

import logging
import time
from typing import List, Tuple

import hvac  # type: ignore[import-untyped]
import requests

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Exception raised for Vault errors."""

    pass


class Vault:
    """Class to interact with Vault through its API."""

    def __init__(self, url: str, ca_cert_path: str):
        self._client = hvac.Client(url=url, verify=ca_cert_path)

    def initialize(
        self, secret_shares: int = 1, secret_threshold: int = 1
    ) -> Tuple[str, List[str]]:
        """Initialize Vault.

        Returns:
            A tuple containing the root token and the unseal keys.
        """
        initialize_response = self._client.sys.initialize(
            secret_shares=secret_shares, secret_threshold=secret_threshold
        )
        logger.info("Vault is initialized")
        return initialize_response["root_token"], initialize_response["keys"]

    def is_initialized(self) -> bool:
        """Returns whether Vault is initialized."""
        return self._client.sys.is_initialized()

    def is_sealed(self) -> bool:
        """Returns whether Vault is sealed."""
        return self._client.sys.is_sealed()

    def wait_for_unseal(self, timeout: int = 30) -> None:
        """Waits for Vault to be unsealed.

        Expected to be called after attempting to unseal Vault.
        If it times out, raises a TimeoutError.

        Args:
            timeout: Timeout in seconds.
        """
        initial_time = time.time()
        while time.time() - initial_time < timeout:
            if not self.is_sealed():
                return
            logger.info("Vault is sealed, waiting for unseal")
            time.sleep(2)

        # One more check after the loop to catch any edge cases.
        if not self.is_sealed():
            return

        raise TimeoutError(f"Vault is still sealed {timeout} seconds")

    def unseal(self, unseal_keys: List[str]) -> None:
        """Unseal Vault."""
        for unseal_key in unseal_keys:
            self._client.sys.submit_unseal_key(unseal_key)
        logger.info("Vault is unsealed")

    def is_api_available(self) -> bool:
        """Returns whether Vault is available."""
        try:
            self._client.sys.read_health_status()
        except requests.exceptions.ConnectionError:
            return False
        return True

    def set_token(self, token: str) -> None:
        """Sets the Vault token for authentication."""
        self._client.token = token

    def remove_raft_node(self, node_id: str) -> None:
        """Remove raft peer."""
        self._client.sys.remove_raft_node(server_id=node_id)
        logger.info("Removed raft node %s", node_id)

    def is_node_in_raft_peers(self, node_id: str) -> bool:
        """Check if node is in raft peers."""
        raft_config = self._client.sys.read_raft_config()
        for peer in raft_config["data"]["config"]["servers"]:
            if peer["node_id"] == node_id:
                return True
        return False

    def get_num_raft_peers(self) -> int:
        """Returns the number of raft peers."""
        raft_config = self._client.sys.read_raft_config()
        return len(raft_config["data"]["config"]["servers"])

    def enable_approle_auth(self) -> None:
        """Enable the AppRole authentication method in Vault, if not already enabled."""
        if "approle/" not in self._client.sys.list_auth_methods():
            self._client.sys.enable_auth_method("approle")
            logger.info("Enabled approle auth method")

    def configure_kv_mount(self, name: str):
        """Ensure a KV mount is enabled."""
        if name + "/" not in self._client.sys.list_mounted_secrets_engines():
            self._client.sys.enable_secrets_engine(
                backend_type="kv-v2",
                description="Charm created KV backend",
                path=name,
            )

    def configure_kv_policy(self, policy: str, mount: str):
        """Create/update a policy within vault to access the KV mount."""
        with open("src/templates/kv_mount.hcl", "r") as fd:
            mount_policy = fd.read()
        self._client.sys.create_or_update_policy(policy, mount_policy.format(mount=mount))

    def enable_audit_device(self, device_type: str, path: str) -> None:
        """Enable a new audit device at the supplied path."""
        if device_type + "/" not in self._client.sys.list_enabled_audit_devices()["data"].keys():
            if (
                self._client.sys.enable_audit_device(
                    device_type=device_type,
                    options={"file_path": path},
                ).status_code
                != 204
            ):
                logger.error(
                    "Failed to enable audit device of type: %s, using path: %s", device_type, path
                )
            logger.info("Enabled audit device of type: %s, using path: %s", device_type, path)
        logger.debug("Audit device of type: %s, using path: %s already enabled", device_type, path)

    def configure_approle(self, name: str, cidrs: List[str], policies: List[str]) -> str:
        """Create/update a role within vault associating the supplied policies."""
        self._client.auth.approle.create_or_update_approle(
            name,
            token_ttl="60s",
            token_max_ttl="60s",
            token_policies=policies,
            bind_secret_id="true",
            token_bound_cidrs=cidrs,
        )
        response = self._client.auth.approle.read_role_id(name)
        return response["data"]["role_id"]

    def generate_role_secret_id(self, name: str, cidrs: List[str]) -> str:
        """Generate a new secret tied to an AppRole."""
        response = self._client.auth.approle.generate_secret_id(name, cidr_list=cidrs)
        return response["data"]["secret_id"]

    def read_role_secret(self, name: str, id: str) -> dict:
        """Get definition of a secret tied to an AppRole."""
        response = self._client.auth.approle.read_secret_id(name, id)
        return response["data"]
