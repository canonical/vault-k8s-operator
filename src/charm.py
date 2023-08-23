#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
from typing import List, Optional, Tuple

from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV2,
)
from ops.charm import ActionEvent, CharmBase, ConfigChangedEvent, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, ModelError, WaitingStatus
from ops.pebble import Layer

from vault import Vault

logger = logging.getLogger(__name__)

VAULT_STORAGE_PATH = "/srv"
PEER_RELATION_NAME = "vault-peers"


class VaultCharm(CharmBase):
    """Main class for to handle Juju events for the vault-k8s charm."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args):
        super().__init__(*args)
        self.tls_certificates = TLSCertificatesProvidesV2(self, "certificates")
        self._service_name = self._container_name = "vault"
        self._container = self.unit.get_container(self._container_name)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self.framework.observe(self.on.vault_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.get_root_token_action, self._on_get_root_token_action)
        self.service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="vault", port=self.VAULT_PORT)],
        )

    def _on_install(self, event: InstallEvent):
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
        vault.wait_for_api_available()
        root_token, unseal_keys = vault.initialize()
        self._set_peer_relation_vault_initialization_secret(root_token, unseal_keys)
        vault.set_token(token=root_token)
        vault.unseal(unseal_keys=unseal_keys)
        role_id, secret_id = vault.bootstrap()
        self._set_peer_relation_vault_approle_secret(
            vault_role_id=role_id, vault_secret_id=secret_id
        )
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handler triggered whenever there is a config-changed event.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self.unit.is_leader():
            return
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation")
            event.defer()
            return
        root_token, unseal_keys = self._get_peer_relation_vault_initialization_secret()
        if not root_token or not unseal_keys:
            self.unit.status = WaitingStatus("Waiting for vault initialization secret")
            event.defer()
            return
        self._set_pebble_plan()
        self._patch_storage_ownership()
        vault = Vault(url=self._api_address)
        vault.set_token(token=root_token)
        vault.wait_for_api_available()
        if vault.is_sealed():
            vault.unseal(unseal_keys=unseal_keys)
        self.unit.status = ActiveStatus()

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Handler triggered whenever there is a request made from a requirer charm to vault.

        Args:
            event: CertificateCreationRequestEvent
        """
        role_id, secret_id = self._get_peer_relation_vault_approle_secret()
        if not role_id or not secret_id:
            logger.warning("Vault approle secret not available")
            event.defer()
            return
        vault = Vault(url=self._api_address, role_id=role_id, secret_id=secret_id)
        certificate = vault.issue_certificate(
            certificate_signing_request=event.certificate_signing_request
        )
        self.tls_certificates.set_relation_certificate(
            certificate_signing_request=event.certificate_signing_request,
            certificate=certificate["certificate"],
            ca=certificate["issuing_ca"],
            chain=certificate["ca_chain"],
            relation_id=event.relation_id,
        )

    @property
    def _api_address(self) -> str:
        return f"http://{self._bind_address}:{self.VAULT_PORT}"

    def _set_peer_relation_vault_initialization_secret(
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

    def _get_peer_relation_vault_initialization_secret(
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
        juju_secret = self.model.get_secret(id=juju_secret_id)
        content = juju_secret.get_content()
        return content["roottoken"], json.loads(content["unsealkeys"])

    def _get_peer_relation_vault_approle_secret(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the vault approle secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[str]]: The role id and secret id.
        """
        if not self._is_peer_relation_created():
            return None, None
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        juju_secret_id = peer_relation.data[peer_relation.app].get("vault-approle-secret-id")  # type: ignore[union-attr, index]  # noqa: E501
        if not juju_secret_id:
            return None, None
        juju_secret = self.model.get_secret(id=juju_secret_id)
        content = juju_secret.get_content()
        return content["roleid"], content["secretid"]

    def _set_peer_relation_vault_approle_secret(self, vault_role_id: str, vault_secret_id: str):
        """Set the vault approle secret in the peer relation."""
        if not self._is_peer_relation_created():
            return None, None
        juju_secret_content = {
            "roleid": vault_role_id,
            "secretid": vault_secret_id,
        }
        juju_secret = self.app.add_secret(juju_secret_content)
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        peer_relation.data[self.app].update({"vault-approle-secret-id": juju_secret.id})  # type: ignore[union-attr]  # noqa: E501

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
        backends = {"file": {"path": VAULT_STORAGE_PATH}}
        vault_config = {
            "backend": backends,
            "listener": {"tcp": {"tls_disable": True, "address": f"[::]:{self.VAULT_PORT}"}},
            "default_lease_ttl": self.model.config["default_lease_ttl"],
            "max_lease_ttl": self.model.config["max_lease_ttl"],
            "disable_mlock": True,
            "cluster_addr": f"http://{self._bind_address}:{self.VAULT_CLUSTER_PORT}",
            "api_addr": f"http://{self._bind_address}:{self.VAULT_PORT}",
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

    def _patch_storage_ownership(self) -> None:
        """Fix up storage permissions (broken on AWS and GCP otherwise)'.

        Returns:
            None
        """
        command = ["chown", "100:1000", VAULT_STORAGE_PATH]
        self._container.exec(command=command)

    def _on_get_root_token_action(self, event: ActionEvent):
        """Return the root token to the user."""
        root_token, _ = self._get_peer_relation_vault_initialization_secret()
        if not root_token:
            event.fail(message="Vault token not available")
        event.set_results(results={"root-token": root_token})


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
