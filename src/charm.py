#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
from typing import List, Optional, Tuple, Dict, Any

from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from ops.charm import (
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    RelationJoinedEvent,
    RemoveEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    MaintenanceStatus,
    ModelError,
    SecretNotFoundError,
    WaitingStatus,
)
from ops.pebble import Layer

from vault import Vault

logger = logging.getLogger(__name__)

VAULT_RAFT_DATA_PATH = "/vault/raft"
PEER_RELATION_NAME = "vault-peers"


class VaultCharm(CharmBase):
    """Main class for to handle Juju events for the vault-k8s charm."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args):
        super().__init__(*args)
        self._service_name = self._container_name = "vault"
        self._container = self.unit.get_container(self._container_name)
        self.service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="vault", port=self.VAULT_PORT)],
        )
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.vault_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on[PEER_RELATION_NAME].relation_created, self._on_peer_relation_created
        )
        self.framework.observe(self.on.remove, self._on_remove)

    def _on_install(self, event: InstallEvent):
        """Handler triggered when the charm is installed."""
        if not self.unit.is_leader():
            return
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if not self._bind_address:
            self.unit.status = WaitingStatus("Waiting for bind address to be available")
            event.defer()
            return
        self.unit.status = MaintenanceStatus("Initializing vault")
        self._set_pebble_plan()
        vault = Vault(url=self._api_address)
        if not vault.is_api_available():
            self.unit.status = WaitingStatus("Waiting for vault to be available")
            event.defer()
            return
        root_token, unseal_keys = vault.initialize()
        self._set_initialization_secret_in_peer_relation(root_token, unseal_keys)
        vault.set_token(token=root_token)
        vault.unseal(unseal_keys=unseal_keys)
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handler triggered whenever there is a config-changed event.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation")
            event.defer()
            return
        root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
        if not root_token or not unseal_keys:
            self.unit.status = WaitingStatus("Waiting for vault initialization secret")
            event.defer()
            return
        if not self.unit.is_leader() and len(self._other_peer_unit_addresses()) == 0:
            self.unit.status = WaitingStatus("Waiting for other units to provide their addresses")
            event.defer()
            return
        self.unit.status = MaintenanceStatus("Preparing vault")
        self._set_pebble_plan()
        vault = Vault(url=self._api_address)
        vault.set_token(token=root_token)
        if not vault.is_api_available():
            self.unit.status = WaitingStatus("Waiting for vault to be available")
            event.defer()
            return
        if not vault.is_initialized():
            self.unit.status = WaitingStatus("Waiting for vault to be initialized")
            event.defer()
            return
        if vault.is_sealed():
            vault.unseal(unseal_keys=unseal_keys)
        self._set_peer_relation_unit_address()
        self.unit.status = ActiveStatus()

    def _on_peer_relation_created(self, event: RelationJoinedEvent) -> None:
        """Handle relation-joined event for the replicas relation."""
        self._set_peer_relation_unit_address()

    def _on_remove(self, event: RemoveEvent):
        """Handler triggered when the charm is removed.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        if not self._container.can_connect():
            return
        root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
        if root_token:
            vault = Vault(url=self._api_address)
            vault.set_token(token=root_token)
            if vault.is_api_available() and vault.node_in_raft_peers(node_id=self._node_id):
                vault.remove_raft_node(node_id=self._node_id)
        if self._vault_service_is_running():
            self._container.stop(self._service_name)
        self._container.remove_path(path=f"{VAULT_RAFT_DATA_PATH}/*", recursive=True)

    def _vault_service_is_running(self) -> bool:
        """Check if the vault service is running."""
        try:
            self._container.get_service(service_name=self._service_name)
        except ModelError:
            return False
        return True

    @property
    def _api_address(self) -> str:
        """Returns the API address."""
        return f"http://{self._bind_address}:{self.VAULT_PORT}"

    def _set_initialization_secret_in_peer_relation(
        self, root_token: str, unseal_keys: List[str]
    ) -> None:
        """Set the vault initialization secret in the peer relation.

        Args:
            root_token: The root token.
            unseal_keys: The unseal keys.
        """
        if not self._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        juju_secret_content = {
            "roottoken": root_token,
            "unsealkeys": json.dumps(unseal_keys),
        }
        juju_secret = self.app.add_secret(juju_secret_content)
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        peer_relation.data[self.app].update({"vault-initialization-secret-id": juju_secret.id})  # type: ignore[union-attr]  # noqa: E501

    def _get_initialization_secret_from_peer_relation(
        self,
    ) -> Tuple[Optional[str], Optional[List[str]]]:
        """Get the vault initialization secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[List[str]]]: The root token and unseal keys.
        """
        if not self._is_peer_relation_created():
            return None, None
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        juju_secret_id = peer_relation.data[peer_relation.app].get(  # type: ignore[union-attr, index]  # noqa: E501
            "vault-initialization-secret-id"
        )
        if not juju_secret_id:
            return None, None
        try:
            juju_secret = self.model.get_secret(id=juju_secret_id)
        except SecretNotFoundError:
            return None, None
        content = juju_secret.get_content()
        return content["roottoken"], json.loads(content["unsealkeys"])

    def _is_peer_relation_created(self) -> bool:
        """Check if the peer relation is created."""
        return bool(self.model.get_relation(PEER_RELATION_NAME))

    def _set_pebble_plan(self) -> None:
        """Set the pebble plan if different from the currently applied one."""
        plan = self._container.get_plan()
        layer = self._vault_layer
        if plan.services != layer.services:
            self._container.add_layer(self._container_name, layer, combine=True)
            self._container.replan()
            logger.info("Pebble layer added")

    @property
    def _bind_address(self) -> Optional[str]:
        """Fetches bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            return None
        try:
            binding = self.model.get_binding(peer_relation)
            if not binding:
                return None
            return str(binding.network.bind_address)
        except ModelError:
            return None

    @property
    def _vault_layer(self) -> Layer:
        """Returns pebble layer to start Vault.

        Vault config options:
            backend: Configures the storage backend where Vault data is stored.
            listener: Configures how Vault is listening for API requests.
            default_lease_ttl: Specifies the default lease duration for Vault's tokens and secrets.
            max_lease_ttl: Specifies the maximum possible lease duration for Vault's tokens and
                secrets.
            disable_mlock: mlock() ensures memory from a process on a Linux system isn't swapped
                (written) to disk. Enabling mlock would require the operator to add IPC_LOCK
                capabilities to the vault pod which isn't even necessary since Kubernetes, by
                default, doesn't enable swap.
            cluster_addr: Specifies the address to advertise to other Vault servers in the cluster
                for request forwarding.
            api_addr: Specifies the address (full URL) to advertise to other Vault servers in the
                cluster for client redirection

        Returns:
            Layer: Pebble Layer
        """
        vault_config = {
            "ui": True,
            "storage": {"raft": self._get_raft_config()},
            "listener": {"tcp": {"tls_disable": True, "address": f"[::]:{self.VAULT_PORT}"}},
            "default_lease_ttl": self.model.config["default_lease_ttl"],
            "max_lease_ttl": self.model.config["max_lease_ttl"],
            "disable_mlock": True,
            "cluster_addr": f"http://{self._bind_address}:{self.VAULT_CLUSTER_PORT}",
            "api_addr": self._api_address,
        }

        return Layer(
            {
                "summary": "vault layer",
                "description": "pebble config layer for vault",
                "services": {
                    "vault": {
                        "override": "replace",
                        "summary": "vault",
                        "command": "/usr/local/bin/docker-entrypoint.sh server",
                        "startup": "enabled",
                        "environment": {
                            "VAULT_LOCAL_CONFIG": json.dumps(vault_config),
                            "VAULT_API_ADDR": f"http://[::]:{self.VAULT_PORT}",
                        },
                    }
                },
            }
        )

    def _set_peer_relation_unit_address(self) -> None:
        """Set the unit address in the peer relation."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            raise RuntimeError("Peer relation not created")
        peer_relation.data[self.unit].update({"unit-address": self._api_address})

    def _get_peer_relation_unit_addresses(self) -> List[str]:
        """Returns list of peer unit addresses."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        unit_addresses = []
        if not peer_relation:
            return []
        for peer in peer_relation.units:
            if "unit-address" in peer_relation.data[peer]:
                unit_addresses.append(peer_relation.data[peer]["unit-address"])
        return unit_addresses

    def _other_peer_unit_addresses(self) -> List[str]:
        """Returns list of other peer unit addresses."""
        return [
            unit_address
            for unit_address in self._get_peer_relation_unit_addresses()
            if unit_address != self._api_address
        ]

    def _get_raft_config(self) -> Dict[str, Any]:
        """Returns raft config for vault."""
        retry_join = [
            {"leader_api_addr": unit_address} for unit_address in self._other_peer_unit_addresses()
        ]
        raft_config = {
            "path": VAULT_RAFT_DATA_PATH,
            "node_id": self._node_id,
        }
        if retry_join:
            raft_config["retry_join"] = retry_join
        return raft_config

    @property
    def _node_id(self) -> str:
        return f"{self.model.name}-{self.unit.name}"


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
