#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains all the specificities to communicate with Vault through its API."""

import logging
from typing import List, Optional, Tuple

import hvac  # type: ignore[import-untyped]
import requests
from hvac.exceptions import VaultError  # type: ignore[import-untyped]
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)
RAFT_STATE_ENDPOINT = "v1/sys/storage/raft/autopilot/state"


class VaultClientError(Exception):
    """Custom exception to pass errors with Vault client calls."""

    def __init__(self, message: str = "An error occurred while interacting with Vault client."):
        self.message = message
        super().__init__(self.message)


class Vault:
    """Class to interact with Vault through its API."""

    def __init__(self, url: str, ca_cert_path: str):
        self._client = hvac.Client(url=url, verify=ca_cert_path)

    def initialize(
        self, secret_shares: int = 1, secret_threshold: int = 1
    ) -> Optional[Tuple[str, List[str]]]:
        """Initialize Vault.

        Returns:
            A tuple containing the root token and the unseal keys.
                A None if the initialization fails.
        """
        try:
            initialize_response = self._client.sys.initialize(
                secret_shares=secret_shares, secret_threshold=secret_threshold
            )
            logger.info("Vault is initialized")
            return initialize_response["root_token"], initialize_response["keys"]
        except (RequestException, VaultError) as e:
            logger.error("Error initializing Vault: %s", e)
            return None

    def is_initialized(self) -> bool:
        """Returns whether Vault is initialized."""
        return self._client.sys.is_initialized()

    def is_sealed(self) -> bool:
        """Returns whether Vault is sealed."""
        return self._client.sys.is_sealed()

    def is_active(self) -> bool:
        """Returns whether Vault is active."""
        try:
            response = self._client.sys.read_health_status(standby_ok=True)
            return response.status_code == 200
        except (RequestException, VaultError) as e:
            logger.error("Error checking Vault health: %s", e)
            return False

    def unseal(self, unseal_keys: List[str]) -> None:
        """Unseal Vault."""
        try:
            for unseal_key in unseal_keys:
                self._client.sys.submit_unseal_key(unseal_key)
            logger.info("Vault is unsealed")
        except (RequestException, VaultError) as e:
            logger.error("Error unsealing Vault: %s", e)
            raise VaultClientError

    def is_api_available(self) -> bool:
        """Returns whether Vault is available."""
        try:
            self._client.sys.read_health_status()
            return True
        except (RequestException, VaultError) as e:
            logger.error("Vault API is not available: %s", e)
            return False

    def set_token(self, token: str) -> None:
        """Sets the Vault token for authentication."""
        self._client.token = token

    def remove_raft_node(self, node_id: str) -> None:
        """Remove raft peer."""
        try:
            self._client.sys.remove_raft_node(server_id=node_id)
            logger.info("Removed raft node %s", node_id)
        except (RequestException, VaultError) as e:
            logger.error("Error removing raft node: %s", e)
            raise VaultClientError

    def is_node_in_raft_peers(self, node_id: str) -> bool:
        """Check if node is in raft peers."""
        try:
            raft_config = self._client.sys.read_raft_config()
            for peer in raft_config["data"]["config"]["servers"]:
                if peer["node_id"] == node_id:
                    return True
        except (RequestException, VaultError) as e:
            logger.error("Error reading raft config: %s", e)
            raise VaultClientError
        return False

    def get_num_raft_peers(self) -> int:
        """Returns the number of raft peers."""
        try:
            raft_config = self._client.sys.read_raft_config()
            return len(raft_config["data"]["config"]["servers"])
        except (RequestException, VaultError) as e:
            logger.error("Error reading raft config: %s", e)
            raise VaultClientError

    def enable_approle_auth(self) -> None:
        """Enable the AppRole authentication method in Vault, if not already enabled."""
        try:
            if "approle/" not in self._client.sys.list_auth_methods():
                self._client.sys.enable_auth_method("approle")
                logger.info("Enabled approle auth method")
        except (RequestException, VaultError) as e:
            logger.error("Error enabling approle auth method: %s", e)
            raise VaultClientError

    def configure_kv_mount(self, name: str):
        """Ensure a KV mount is enabled."""
        try:
            if name + "/" not in self._client.sys.list_mounted_secrets_engines():
                self._client.sys.enable_secrets_engine(
                    backend_type="kv-v2",
                    description="Charm created KV backend",
                    path=name,
                )
        except (RequestException, VaultError) as e:
            logger.error("Error enabling KV mount: %s", e)
            raise VaultClientError

    def configure_kv_policy(self, policy: str, mount: str):
        """Create/update a policy within vault to access the KV mount."""
        with open("src/templates/kv_mount.hcl", "r") as fd:
            mount_policy = fd.read()
        try:
            self._client.sys.create_or_update_policy(policy, mount_policy.format(mount=mount))
        except (RequestException, VaultError) as e:
            logger.error("Error configuring KV policy: %s", e)
            raise VaultClientError

    def audit_device_enabled(self, device_type: str, path: str) -> bool:
        """Check if audit device is enabled."""
        try:
            audit_devices = self._client.sys.list_enabled_audit_devices()
            if f"{device_type}/" not in audit_devices["data"].keys():
                return False
            if audit_devices["data"][f"{device_type}/"]["options"]["file_path"] != path:
                return False
            return True
        except (RequestException, VaultError) as e:
            logger.error("Error checking audit device: %s", e)
            raise VaultClientError

    def enable_audit_device(self, device_type: str, path: str) -> None:
        """Enable a new audit device at the supplied path."""
        try:
            self._client.sys.enable_audit_device(
                device_type=device_type,
                options={"file_path": path},
            )
            logger.info("Enabled audit device %s", device_type)
        except (RequestException, VaultError) as e:
            logger.error("Error enabling audit device: %s", e)
            raise VaultClientError

    def create_snapshot(self) -> requests.Response:
        """Create a snapshot of the Vault data."""
        try:
            return self._client.sys.take_raft_snapshot()
        except (RequestException, VaultError) as e:
            logger.error("Error creating snapshot: %s", e)
            raise VaultClientError

    def restore_snapshot(self, snapshot: bytes) -> requests.Response:
        """Restore a snapshot of the Vault data.

        Uses force_restore_raft_snapshot to restore the snapshot
        even if the unseal key used at backup time is different from the current one.
        """
        try:
            return self._client.sys.force_restore_raft_snapshot(snapshot)
        except (RequestException, VaultError) as e:
            logger.error("Error restoring snapshot: %s", e)
            raise VaultClientError

    def configure_approle(self, name: str, cidrs: List[str], policies: List[str]) -> str:
        """Create/update a role within vault associating the supplied policies."""
        try:
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
        except (RequestException, VaultError) as e:
            logger.error("Error configuring AppRole: %s", e)
            raise VaultClientError

    def generate_role_secret_id(self, name: str, cidrs: List[str]) -> str:
        """Generate a new secret tied to an AppRole."""
        try:
            response = self._client.auth.approle.generate_secret_id(name, cidr_list=cidrs)
            return response["data"]["secret_id"]
        except (RequestException, VaultError) as e:
            logger.error("Error generating secret ID: %s", e)
            raise VaultClientError

    def read_role_secret(self, name: str, id: str) -> dict:
        """Get definition of a secret tied to an AppRole."""
        try:
            response = self._client.auth.approle.read_secret_id(name, id)
            return response["data"]
        except (RequestException, VaultError) as e:
            logger.error("Error reading secret: %s", e)
            raise VaultClientError

    def get_raft_cluster_state(self) -> dict:
        """Get raft cluster state."""
        try:
            response = self._client.adapter.get(RAFT_STATE_ENDPOINT)
            return response["data"]
        except (RequestException, VaultError) as e:
            logger.error("Error getting raft cluster state: %s", e)
            raise VaultClientError

    def is_raft_cluster_healthy(self) -> bool:
        """Check if raft cluster is healthy."""
        return self.get_raft_cluster_state()["healthy"]
