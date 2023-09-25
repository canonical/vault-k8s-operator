#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""
import json
import logging
from typing import Dict, List, Optional, Tuple

import hcl  # type: ignore[import]
from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from charms.tls_certificates_interface.v2.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
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
from ops.pebble import ChangeError, Layer, PathError

from vault import Vault

logger = logging.getLogger(__name__)

VAULT_STORAGE_PATH = "/vault/raft"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
VAULT_CONFIG_FILE_PATH = "/vault/config/vault.hcl"
TLS_CERT_FILE_PATH = "/vault/certs/cert.pem"
TLS_KEY_FILE_PATH = "/vault/certs/key.pem"
TLS_CA_FILE_PATH = "/vault/certs/ca.pem"
PEER_RELATION_NAME = "vault-peers"


def render_vault_config_file(
    default_lease_ttl: str,
    max_lease_ttl: str,
    cluster_address: str,
    api_address: str,
    tls_cert_file: str,
    tls_key_file: str,
    tcp_address: str,
    raft_storage_path: str,
    node_id: str,
    retry_joins: List[Dict[str, str]],
) -> str:
    """Render the Vault config file."""
    jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR_PATH))
    template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
    content = template.render(
        default_lease_ttl=default_lease_ttl,
        max_lease_ttl=max_lease_ttl,
        cluster_address=cluster_address,
        api_address=api_address,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        tcp_address=tcp_address,
        raft_storage_path=raft_storage_path,
        node_id=node_id,
        retry_joins=retry_joins,
    )
    return content


class PeerSecretError(Exception):
    """Exception raised when a peer secret is not found."""

    def __init__(
        self, secret_name: str, message: str = "Could not retrieve secret from peer relation"
    ):
        self.secret_name = secret_name
        self.message = message
        super().__init__(self.message)


def generate_vault_certificates(subject: str, sans_ip: List[str]) -> Tuple[str, str, str]:
    """Generate Vault certificates valid for 50 years.

    Returns:
        Tuple[str, str, str]: Private key, certificate, CA certificate
    """
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        subject="Vault self signed CA",
        validity=365 * 50,
    )
    vault_private_key = generate_private_key()
    csr = generate_csr(
        private_key=vault_private_key, subject=subject, sans_ip=sans_ip, sans_dns=[subject]
    )
    vault_certificate = generate_certificate(
        ca=ca_certificate,
        ca_key=ca_private_key,
        csr=csr,
        validity=365 * 50,
    )
    return vault_private_key.decode(), vault_certificate.decode(), ca_certificate.decode()


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
        """Handler triggered when the charm is installed.

        Sets pebble plan, initializes vault, and unseals vault.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        self._delete_vault_data()
        if not self.unit.is_leader():
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if not self._bind_address or not self._ingress_address:
            self.unit.status = WaitingStatus(
                "Waiting for bind and ingress addresses to be available"
            )
            event.defer()
            return
        self.unit.status = MaintenanceStatus("Initializing vault")
        try:
            (
                private_key,
                certificate,
                ca_certificate,
            ) = self._get_certificates_secret_in_peer_relation()
        except PeerSecretError:
            logger.info("Vault certificate secret not set in peer relation")
            private_key, certificate, ca_certificate = generate_vault_certificates(
                subject=self._certificate_subject,
                sans_ip=[self._bind_address, self._ingress_address],
            )
            self._set_certificates_secret_in_peer_relation(
                private_key=private_key, certificate=certificate, ca_certificate=ca_certificate
            )
        if not self._certificate_pushed_to_workload(
            certificate=certificate,
            private_key=private_key,
            ca_certificate=ca_certificate,
        ):
            self._push_certificates_to_workload(
                certificate=certificate,
                private_key=private_key,
                ca_certificate=ca_certificate,
            )
        self._generate_vault_config_file()
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

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handler triggered whenever there is a config-changed event.

        Configures pebble layer, sets the unit address in the peer relation, starts the vault
        service, and unseals Vault.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation")
            event.defer()
            return
        try:
            root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
        except PeerSecretError:
            self.unit.status = WaitingStatus("Waiting for vault initialization secret")
            event.defer()
            return
        if not self.unit.is_leader() and len(self._other_peer_node_api_addresses()) == 0:
            self.unit.status = WaitingStatus("Waiting for other units to provide their addresses")
            event.defer()
            return
        try:
            (
                private_key,
                certificate,
                ca_certificate,
            ) = self._get_certificates_secret_in_peer_relation()
        except PeerSecretError:
            self.unit.status = WaitingStatus("Waiting for vault certificate to be available")
            event.defer()
            return
        if not self._certificate_pushed_to_workload(
            private_key=private_key,
            certificate=certificate,
            ca_certificate=ca_certificate,
        ):
            self._push_certificates_to_workload(
                private_key=private_key,
                certificate=certificate,
                ca_certificate=ca_certificate,
            )
        self.unit.status = MaintenanceStatus("Preparing vault")
        self._generate_vault_config_file()
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
        self._set_peer_relation_node_api_address()
        self.unit.status = ActiveStatus()

    def _on_peer_relation_created(self, event: RelationJoinedEvent) -> None:
        """Handle relation-joined event for the replicas relation."""
        self._set_peer_relation_node_api_address()

    def _on_remove(self, event: RemoveEvent):
        """Handler triggered when the charm is removed.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        if not self._container.can_connect():
            return
        try:
            root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
            if self._bind_address:
                vault = Vault(url=self._api_address)
                vault.set_token(token=root_token)
                if (
                    vault.is_api_available()
                    and vault.is_node_in_raft_peers(node_id=self._node_id)
                    and vault.get_num_raft_peers() > 1
                ):
                    vault.remove_raft_node(node_id=self._node_id)
        except PeerSecretError:
            logger.info("Vault initialization secret not set in peer relation")
        finally:
            if self._vault_service_is_running():
                try:
                    self._container.stop(self._service_name)
                except ChangeError:
                    logger.warning("Failed to stop Vault service")
                    pass
            self._delete_vault_data()

    def _delete_vault_data(self) -> None:
        """Delete Vault's data."""
        try:
            self._container.remove_path(path=f"{VAULT_STORAGE_PATH}/vault.db")
            logger.info("Removed Vault's main database")
        except PathError:
            logger.info("No Vault database to remove")
        try:
            self._container.remove_path(path=f"{VAULT_STORAGE_PATH}/raft/raft.db")
            logger.info("Removed Vault's Raft database")
        except PathError:
            logger.info("No Vault raft database to remove")

    def _vault_service_is_running(self) -> bool:
        """Check if the vault service is running."""
        try:
            self._container.get_service(service_name=self._service_name)
        except ModelError:
            return False
        return True

    @property
    def _api_address(self) -> str:
        """Returns the API address.

        Example: "https://1.2.3.4:8200"
        """
        return f"https://{self._bind_address}:{self.VAULT_PORT}"

    def _push_certificates_to_workload(
        self,
        private_key: str,
        certificate: str,
        ca_certificate: str,
    ) -> None:
        """Push the certificates to the workload."""
        self._container.push(path=TLS_CERT_FILE_PATH, source=certificate)
        self._container.push(path=TLS_KEY_FILE_PATH, source=private_key)
        self._container.push(path=TLS_CA_FILE_PATH, source=ca_certificate)
        logger.info("Pushed certificates to workload")

    def _certificate_pushed_to_workload(
        self, private_key: str, certificate: str, ca_certificate: str
    ) -> bool:
        """Check if the certificates are pushed to the workload."""
        if not self._container.exists(path=TLS_CERT_FILE_PATH):
            return False
        if not self._container.exists(path=TLS_KEY_FILE_PATH):
            return False
        if not self._container.exists(path=TLS_CA_FILE_PATH):
            return False
        existing_certificate = self._container.pull(path=TLS_CERT_FILE_PATH)
        if existing_certificate.read() != certificate:
            return False
        existing_private_key = self._container.pull(path=TLS_KEY_FILE_PATH)
        if existing_private_key.read() != private_key:
            return False
        existing_ca_certificate = self._container.pull(path=TLS_CA_FILE_PATH)
        if existing_ca_certificate.read() != ca_certificate:
            return False
        return True

    def _config_file_pushed_to_workload(self) -> bool:
        """Check if the config file is pushed to the workload."""
        if not self._container.exists(path=VAULT_CONFIG_FILE_PATH):
            return False
        return True

    def _generate_vault_config_file(self) -> None:
        """Handles creation of the Vault config file."""
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": TLS_CA_FILE_PATH,
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]
        logger.info("Retry joins: %s", retry_joins)

        content = render_vault_config_file(
            default_lease_ttl=self.model.config["default_lease_ttl"],
            max_lease_ttl=self.model.config["max_lease_ttl"],
            cluster_address=f"https://{self._bind_address}:{self.VAULT_CLUSTER_PORT}",
            api_address=self._api_address,
            tcp_address=f"[::]:{self.VAULT_PORT}",
            tls_cert_file=TLS_CERT_FILE_PATH,
            tls_key_file=TLS_KEY_FILE_PATH,
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
        )
        if not self._config_file_content_matches(content=content):
            self._push_config_file_to_workload(content=content)

    def _config_file_content_matches(self, content: str) -> bool:
        """Returns whether the vault config file content matches the provided content.

        Returns:
            bool: Whether the vault config file content matches
        """
        if not self._container.exists(path=VAULT_CONFIG_FILE_PATH):
            return False
        existing_content = self._container.pull(path=VAULT_CONFIG_FILE_PATH)
        existing_config_hcl = hcl.load(existing_content)
        new_content_hcl = hcl.loads(content)

        if existing_config_hcl != new_content_hcl:
            return False
        return True

    def _push_config_file_to_workload(self, content: str):
        """Push the config file to the workload."""
        self._container.push(path=VAULT_CONFIG_FILE_PATH, source=content)
        logger.info("Pushed %s config file", VAULT_CONFIG_FILE_PATH)

    def _set_certificates_secret_in_peer_relation(
        self,
        private_key: str,
        certificate: str,
        ca_certificate: str,
    ) -> None:
        """Set the vault certificate secret in the peer relation.

        Args:
            private_key: Private key
            certificate: certificate
            ca_certificate: CA certificate
        """
        if not self._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        juju_secret_content = {
            "privatekey": private_key,
            "certificate": certificate,
            "cacertificate": ca_certificate,
        }
        juju_secret = self.app.add_secret(juju_secret_content, label="vault-certificate")
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        peer_relation.data[self.app].update({"vault-certificates-secret-id": juju_secret.id})  # type: ignore[union-attr]  # noqa: E501
        logger.info("Vault certificate secret set in peer relation")

    def _get_certificates_secret_in_peer_relation(
        self,
    ) -> Tuple[str, str, str]:
        """Get the vault certificate secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[str], Optional[str]]: The private key, certificate and
                CA certificate.
        """
        try:
            peer_relation = self.model.get_relation(PEER_RELATION_NAME)
            juju_secret_id = peer_relation.data[peer_relation.app].get(  # type: ignore[union-attr, index]  # noqa: E501
                "vault-certificates-secret-id"
            )
            juju_secret = self.model.get_secret(id=juju_secret_id)
            content = juju_secret.get_content()
            return content["privatekey"], content["certificate"], content["cacertificate"]
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name="vault-certificates-secret-id")

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
        juju_secret = self.app.add_secret(juju_secret_content, label="vault-initialization")
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        peer_relation.data[self.app].update({"vault-initialization-secret-id": juju_secret.id})  # type: ignore[union-attr]  # noqa: E501

    def _get_initialization_secret_from_peer_relation(self) -> Tuple[str, List[str]]:
        """Get the vault initialization secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[List[str]]]: The root token and unseal keys.
        """
        try:
            peer_relation = self.model.get_relation(PEER_RELATION_NAME)
            juju_secret_id = peer_relation.data[peer_relation.app].get(  # type: ignore[union-attr, index]  # noqa: E501
                "vault-initialization-secret-id"
            )
            juju_secret = self.model.get_secret(id=juju_secret_id)
            content = juju_secret.get_content()
            return content["roottoken"], json.loads(content["unsealkeys"])
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name="vault-initialization-secret-id")

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
    def _ingress_address(self) -> Optional[str]:
        """Fetches ingress address from peer relation and returns it.

        Returns:
            str: Ingress address
        """
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            return None
        try:
            binding = self.model.get_binding(peer_relation)
            if not binding:
                return None
            return str(binding.network.ingress_address)
        except ModelError:
            return None

    @property
    def _vault_layer(self) -> Layer:
        """Returns pebble layer to start Vault."""
        return Layer(
            {
                "summary": "vault layer",
                "description": "pebble config layer for vault",
                "services": {
                    "vault": {
                        "override": "replace",
                        "summary": "vault",
                        "command": f"vault server -config={VAULT_CONFIG_FILE_PATH}",
                        "startup": "enabled",
                    }
                },
            }
        )

    def _set_peer_relation_node_api_address(self) -> None:
        """Set the unit address in the peer relation."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            raise RuntimeError("Peer relation not created")
        peer_relation.data[self.unit].update({"node_api_address": self._api_address})

    def _get_peer_relation_node_api_addresses(self) -> List[str]:
        """Returns list of peer unit addresses."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        node_api_addresses = []
        if not peer_relation:
            return []
        for peer in peer_relation.units:
            if "node_api_address" in peer_relation.data[peer]:
                node_api_addresses.append(peer_relation.data[peer]["node_api_address"])
        return node_api_addresses

    def _other_peer_node_api_addresses(self) -> List[str]:
        """Returns list of other peer unit addresses.

        We exclude our own unit address from the list.
        """
        return [
            node_api_address
            for node_api_address in self._get_peer_relation_node_api_addresses()
            if node_api_address != self._api_address
        ]

    @property
    def _node_id(self) -> str:
        """Returns node id for vault.

        Example of node id: "vault-k8s-0"
        """
        return f"{self.model.name}-{self.unit.name}"

    @property
    def _certificate_subject(self) -> str:
        return f"{self.app.name}.{self.model.name}.svc.cluster.local"


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
