#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

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
from charms.vault_k8s.v0.vault_kv import NewVaultKvClientAttachedEvent, VaultKvProvides
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
    Relation,
    Secret,
    SecretNotFoundError,
    WaitingStatus,
)
from ops.pebble import ChangeError, Layer, PathError

from vault import Vault

logger = logging.getLogger(__name__)

VAULT_STORAGE_PATH = "/vault/raft"
TLS_CERT_FILE_PATH = "/vault/certs/cert.pem"
TLS_KEY_FILE_PATH = "/vault/certs/key.pem"
TLS_CA_FILE_PATH = "/vault/certs/ca.pem"
PEER_RELATION_NAME = "vault-peers"
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"


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
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.vault_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on[PEER_RELATION_NAME].relation_created, self._on_peer_relation_created
        )
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(
            self.vault_kv.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )

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

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
        """Handler triggered when a new vault-kv client is attached."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can configure a vault-kv client, skipping")
            return

        if not self._is_peer_relation_created():
            logger.debug("Peer relation not created, deferring event")
            event.defer()
            return

        try:
            root_token, _ = self._get_initialization_secret_from_peer_relation()
        except PeerSecretError:
            logger.debug("Vault initialization secret not set in peer relation, deferring event")
            event.defer()
            return

        try:
            (
                _,
                _,
                ca_certificate,
            ) = self._get_certificates_secret_in_peer_relation()
        except PeerSecretError:
            logger.debug("Vault certificate secret not set in peer relation, deferring event")
            event.defer()
            return

        relation = self.model.get_relation(event.relation_name, event.relation_id)

        if relation is None or relation.app is None:
            logger.warning(
                "Relation or remote application is missing,"
                "this should not happen, skipping event"
            )
            return

        vault = Vault(url=self._api_address)
        vault.set_token(token=root_token)

        if not vault.is_api_available():
            logger.debug("Vault is not available, deferring event")
            event.defer()
            return

        vault.enable_approle_auth()

        mount = "charm-" + relation.app.name + "-" + event.mount_suffix
        vault.configure_kv_mount(mount)
        self.vault_kv.set_mount(relation, mount)
        vault_url = self._get_relation_api_address(relation)
        if vault_url is not None:
            self.vault_kv.set_vault_url(relation, vault_url)
        self.vault_kv.set_ca_certificate(relation, ca_certificate)

        nonces = []
        for unit in relation.units:
            egress_subnet = relation.data[unit].get("egress_subnet")
            nonce = relation.data[unit].get("nonce")
            if egress_subnet is None or nonce is None:
                logger.debug(
                    "Skipping configuring access for unit %r, egress_subnet or nonce are missing",
                    unit.name,
                )
                continue
            nonces.append(nonce)
            self._ensure_unit_credentials(vault, relation, unit.name, mount, nonce, egress_subnet)

        # Remove any stale nonce
        credential_nonces = self.vault_kv.get_credentials(relation).keys()
        stale_nonces = set(credential_nonces) - set(nonces)
        self.vault_kv.remove_unit_credentials(relation, stale_nonces)

    def _ensure_unit_credentials(
        self,
        vault: Vault,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnet: str,
    ):
        """Ensures a unit has credentials to access the vault-kv mount."""
        policy_name = role_name = mount + "-" + unit_name.replace("/", "-")
        vault.configure_kv_policy(policy_name, mount)
        role_id = vault.configure_approle(role_name, [egress_subnet], [policy_name])
        secret = self._create_or_update_kv_secret(
            vault,
            relation,
            role_id,
            role_name,
            egress_subnet,
        )
        self.vault_kv.set_unit_credentials(relation, nonce, secret)

    def _create_or_update_kv_secret(
        self,
        vault: Vault,
        relation: Relation,
        role_id: str,
        role_name: str,
        egress_subnet: str,
    ) -> Secret:
        """Create or update a KV secret for a unit.

        Fetch secret id from peer relation, if it exists, update the secret,
        otherwise create it.
        """
        label = KV_SECRET_PREFIX + role_name
        secret_id = self._get_vault_kv_secret_in_peer_relation(label)
        if secret_id is None:
            return self._create_kv_secret(
                vault, relation, role_id, role_name, egress_subnet, label
            )
        else:
            return self._update_kv_secret(
                vault, relation, role_name, egress_subnet, label, secret_id
            )

    def _create_kv_secret(
        self,
        vault: Vault,
        relation: Relation,
        role_id: str,
        role_name: str,
        egress_subnet: str,
        label: str,
    ) -> Secret:
        """Create a vault kv secret, store its id in the peer relation and return it."""
        role_secret_id = vault.generate_role_secret_id(role_name, [egress_subnet])
        secret = self.app.add_secret(
            {"role-id": role_id, "role-secret-id": role_secret_id},
            label=label,
        )
        if secret.id is None:
            raise RuntimeError(f"Unexpected error, just created secret {label!r} has no id")
        self._set_vault_kv_secret_in_peer_relation(label, secret.id)
        secret.grant(relation)
        return secret

    def _update_kv_secret(
        self,
        vault: Vault,
        relation: Relation,
        role_name: str,
        egress_subnet: str,
        label: str,
        secret_id: str,
    ) -> Secret:
        """Update a vault kv secret if the unit subnet is not in the cidr list."""
        secret = self.model.get_secret(id=secret_id, label=label)
        secret.grant(relation)
        credentials = secret.get_content()
        role_secret_id_data = vault.read_role_secret(role_name, credentials["role-secret-id"])
        # if unit subnet is already in cidr_list, skip
        if egress_subnet in role_secret_id_data["cidr_list"]:
            return secret
        credentials["role-secret-id"] = vault.generate_role_secret_id(role_name, [egress_subnet])
        secret.set_content(credentials)
        return secret

    def _get_vault_kv_secrets_in_peer_relation(self) -> Dict[str, str]:
        """Return the vault kv secrets from the peer relation."""
        if not self._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        relation = self.model.get_relation(PEER_RELATION_NAME)
        secrets = json.loads(relation.data[self.app].get("vault-kv-secrets", "{}"))  # type: ignore[union-attr]  # noqa: E501
        return secrets

    def _get_vault_kv_secret_in_peer_relation(self, label: str) -> Optional[str]:
        """Return the vault kv secret id associated to input label from peer relation."""
        return self._get_vault_kv_secrets_in_peer_relation().get(label)

    def _set_vault_kv_secret_in_peer_relation(self, label: str, secret_id: str):
        """Set the vault kv secret in the peer relation."""
        if not self._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        secrets = self._get_vault_kv_secrets_in_peer_relation()
        secrets[label] = secret_id
        relation = self.model.get_relation(PEER_RELATION_NAME)
        relation.data[self.app].update({"vault-kv-secrets": json.dumps(secrets, sort_keys=True)})  # type: ignore[union-attr]  # noqa: E501

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

    def _get_relation_api_address(self, relation: Relation) -> Optional[str]:
        """Fetches api address from relation and returns it.

        Example: "https://10.152.183.20:8200"
        """
        binding = self.model.get_binding(relation)
        if binding is None:
            return None
        return f"https://{binding.network.ingress_address}:{self.VAULT_PORT}"

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
        """Returns pebble layer to start Vault.

        Vault config options:
            ui: Enables the built-in static web UI.
            storage: Configures the storage backend, which represents the location for the
                durable storage of Vault's information.
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
            "listener": {
                "tcp": {
                    "address": f"[::]:{self.VAULT_PORT}",
                    "tls_cert_file": TLS_CERT_FILE_PATH,
                    "tls_key_file": TLS_KEY_FILE_PATH,
                }
            },
            "default_lease_ttl": self.model.config["default_lease_ttl"],
            "max_lease_ttl": self.model.config["max_lease_ttl"],
            "disable_mlock": True,
            "cluster_addr": f"https://{self._bind_address}:{self.VAULT_CLUSTER_PORT}",
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
                            "VAULT_API_ADDR": f"https://[::]:{self.VAULT_PORT}",
                        },
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

    def _get_raft_config(self) -> Dict[str, Any]:
        """Returns raft config for vault.

        Example of raft config:
        {
            "path": "/vault/raft",
            "node_id": "vault-k8s-0",
            "retry_join": [
                {
                    "leader_api_addr": "https://1.2.3.4:8200",
                    "leader_ca_cert_file": "/vault/certs/ca.pem",
                },
                {
                    "leader_api_addr": "https://5.6.7.8:8200",
                    "leader_ca_cert_file": "/vault/certs/ca.pem",
                }
            ]
        }
        """
        retry_join = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": TLS_CA_FILE_PATH,
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]
        raft_config: Dict[str, Any] = {
            "path": VAULT_STORAGE_PATH,
            "node_id": self._node_id,
        }
        if retry_join:
            raft_config["retry_join"] = retry_join
        return raft_config

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
