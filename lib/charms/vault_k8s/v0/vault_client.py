#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Library for interacting with a Vault cluster.

This library shares operations that interact with Vault through its API. It is
intended to be used by charms that need to manage a Vault cluster.
"""


import logging
from typing import List, Tuple

import hvac  # type: ignore[import-untyped]
import requests
from hvac.exceptions import VaultError  # type: ignore[import-untyped]
from requests.exceptions import RequestException

# The unique Charmhub library identifier, never change it
LIBID = "674754a3268d4507b749ec34214706fd"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2


logger = logging.getLogger(__name__)
RAFT_STATE_ENDPOINT = "v1/sys/storage/raft/autopilot/state"


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
        """Return whether Vault is initialized."""
        return self._client.sys.is_initialized()

    def is_sealed(self) -> bool:
        """Return whether Vault is sealed."""
        return self._client.sys.is_sealed()

    def is_active(self) -> bool:
        """Return the health status of Vault.

        Returns:
            True if initialized, unsealed and active, False otherwise.
                Will return True if Vault is in standby mode too (standby_ok=True).
        """
        try:
            health_status = self._client.sys.read_health_status(standby_ok=True)
            return health_status.status_code == 200
        except (VaultError, RequestException) as e:
            logger.error("Error while checking Vault health status: %s", e)
            return False

    def is_api_available(self) -> bool:
        """Return whether Vault is available."""
        try:
            self._client.sys.read_health_status(standby_ok=True)
            return True
        except (VaultError, RequestException) as e:
            logger.error("Error while checking Vault health status: %s", e)
            return False

    def unseal(self, unseal_keys: List[str]) -> None:
        """Unseal Vault."""
        for unseal_key in unseal_keys:
            self._client.sys.submit_unseal_key(unseal_key)
        logger.info("Vault is unsealed")

    def set_token(self, token: str) -> None:
        """Set the Vault token for authentication."""
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
        """Return the number of raft peers."""
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

    def audit_device_enabled(self, device_type: str, path: str) -> bool:
        """Check if audit device is enabled."""
        audit_devices = self._client.sys.list_enabled_audit_devices()
        if f"{device_type}/" not in audit_devices["data"].keys():
            return False
        if audit_devices["data"][f"{device_type}/"]["options"]["file_path"] != path:
            return False
        return True

    def enable_audit_device(self, device_type: str, path: str) -> None:
        """Enable a new audit device at the supplied path."""
        self._client.sys.enable_audit_device(
            device_type=device_type,
            options={"file_path": path},
        )
        logger.info("Enabled audit device %s", device_type)

    def create_snapshot(self) -> requests.Response:
        """Create a snapshot of the Vault data."""
        return self._client.sys.take_raft_snapshot()

    def restore_snapshot(self, snapshot: bytes) -> requests.Response:
        """Restore a snapshot of the Vault data.

        Uses force_restore_raft_snapshot to restore the snapshot
        even if the unseal key used at backup time is different from the current one.
        """
        return self._client.sys.force_restore_raft_snapshot(snapshot)

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

    def get_raft_cluster_state(self) -> dict:
        """Get raft cluster state."""
        response = self._client.adapter.get(RAFT_STATE_ENDPOINT)
        return response["data"]

    def is_raft_cluster_healthy(self) -> bool:
        """Check if raft cluster is healthy."""
        return self.get_raft_cluster_state()["healthy"]
