#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""
import datetime
import json
import logging
import socket
from typing import IO, Dict, List, Optional, Tuple

import hcl  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError
from botocore.response import StreamingBody
from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tls_certificates_interface.v2.tls_certificates import (
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from charms.vault_k8s.v0.vault_kv import NewVaultKvClientAttachedEvent, VaultKvProvides
from jinja2 import Environment, FileSystemLoader
from ops.charm import (
    ActionEvent,
    CharmBase,
    ConfigChangedEvent,
    InstallEvent,
    RelationJoinedEvent,
    RemoveEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    ModelError,
    Relation,
    Secret,
    SecretNotFoundError,
    WaitingStatus,
)
from ops.pebble import ChangeError, Layer, PathError

from s3_session import S3
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
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"
CA_CERTIFICATE_JUJU_SECRET_KEY = "vault-ca-certificates-secret-id"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "vault-ca-certificate"
SEND_CA_CERT_RELATION_NAME = "send-ca-cert"
VAULT_INITIALIZATION_SECRET_LABEL = "vault-initialization"
S3_RELATION_NAME = "s3-parameters"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
BACKUP_KEY_PREFIX = "vault-backup"


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


def config_file_content_matches(existing_content: str, new_content: str) -> bool:
    """Returns whether two Vault config file contents match.

    We check if the retry_join addresses match, and then we check if the rest of the config
    file matches.

    Returns:
        bool: Whether the vault config file content matches
    """
    existing_config_hcl = hcl.loads(existing_content)
    new_content_hcl = hcl.loads(new_content)
    if not existing_config_hcl:
        logger.info("Existing config file is empty")
        return existing_config_hcl == new_content_hcl
    if not new_content_hcl:
        logger.info("New config file is empty")
        return existing_config_hcl == new_content_hcl

    new_retry_joins = new_content_hcl["storage"]["raft"].pop("retry_join", [])
    existing_retry_joins = existing_config_hcl["storage"]["raft"].pop("retry_join", [])

    # If there is only one retry join, it is a dict
    if isinstance(new_retry_joins, dict):
        new_retry_joins = [new_retry_joins]
    if isinstance(existing_retry_joins, dict):
        existing_retry_joins = [existing_retry_joins]

    new_retry_join_api_addresses = set(address["leader_api_addr"] for address in new_retry_joins)
    existing_retry_join_api_addresses = set(
        address["leader_api_addr"] for address in existing_retry_joins
    )
    return (
        new_retry_join_api_addresses == existing_retry_join_api_addresses
        and new_content_hcl == existing_config_hcl
    )


class PeerSecretError(Exception):
    """Exception raised when a peer secret is not found."""

    def __init__(
        self, secret_name: str, message: str = "Could not retrieve secret from peer relation"
    ):
        self.secret_name = secret_name
        self.message = message
        super().__init__(self.message)


class VaultCertsError(Exception):
    """Exception raised when a vault certificate is not found."""

    def __init__(self, message: str = "Could not retrieve vault certificates from local storage"):
        self.message = message
        super().__init__(self.message)


def generate_vault_ca_certificate() -> Tuple[str, str]:
    """Generate Vault CA certificates valid for 50 years.

    Returns:
        Tuple[str, str]: CA Private key, CA certificate
    """
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        subject="Vault self signed CA",
        validity=365 * 50,
    )
    return ca_private_key.decode(), ca_certificate.decode()


def generate_vault_unit_certificate(
    subject: str,
    sans_ip: List[str],
    sans_dns: List[str],
    ca_certificate: bytes,
    ca_private_key: bytes,
) -> Tuple[str, str]:
    """Generate Vault unit certificates valid for 50 years.

    Args:
        subject: Subject of the certificate
        sans_ip: List of IP addresses to add to the SAN
        sans_dns: List of DNS subject alternative names
        ca_certificate: CA certificate
        ca_private_key: CA private key

    Returns:
        Tuple[str, str]: Unit private key, Unit certificate
    """
    vault_private_key = generate_private_key()
    csr = generate_csr(
        private_key=vault_private_key, subject=subject, sans_ip=sans_ip, sans_dns=sans_dns
    )
    vault_certificate = generate_certificate(
        ca=ca_certificate,
        ca_key=ca_private_key,
        csr=csr,
        validity=365 * 50,
    )
    return vault_private_key.decode(), vault_certificate.decode()


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
        self._metrics_endpoint = MetricsEndpointProvider(
            self,
            jobs=[
                {
                    "scheme": "https",
                    "tls_config": {"insecure_skip_verify": True},
                    "metrics_path": "/v1/sys/metrics",
                    "static_configs": [{"targets": [f"*:{self.VAULT_PORT}"]}],
                }
            ],
        )
        self.ingress = IngressPerAppRequirer(
            charm=self,
            port=self.VAULT_PORT,
            strip_prefix=True,
            scheme=lambda: "https",
        )
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.vault_pebble_ready, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_created, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_changed, self._configure)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.on.restore_backup_action, self._on_restore_backup_action)
        self.framework.observe(
            self.vault_kv.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )
        self.framework.observe(
            self.on[SEND_CA_CERT_RELATION_NAME].relation_joined,
            self._on_send_ca_cert_relation_joined,
        )

    def _on_install(self, event: InstallEvent):
        """Handler triggered when the charm is installed."""
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            event.defer()
            return
        self._delete_vault_data()

    def _configure(self, event: ConfigChangedEvent) -> None:
        """Handler triggered whenever there is a config-changed event.

        Configures pebble layer, sets the unit address in the peer relation, starts the vault
        service, and unseals Vault.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting to be able to connect to vault unit")
            return
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation")
            return
        if not self._bind_address or not self._ingress_address:
            self.unit.status = WaitingStatus(
                "Waiting for bind and ingress addresses to be available"
            )
            return
        if not self.unit.is_leader() and len(self._other_peer_node_api_addresses()) == 0:
            self.unit.status = WaitingStatus("Waiting for other units to provide their addresses")
            return
        if not self.unit.is_leader() and not self._ca_certificate_set_in_peer_relation():
            self.unit.status = WaitingStatus(
                "Waiting for CA certificate to be set in peer relation"
            )
            return
        if not self.unit.is_leader() and not self._initialization_secret_set_in_peer_relation():
            self.unit.status = WaitingStatus(
                "Waiting for initialization secret to be set in peer relation"
            )
            return
        if self.unit.is_leader() and not self._ca_certificate_set_in_peer_relation():
            ca_private_key, ca_certificate = generate_vault_ca_certificate()
            self._set_ca_certificate_secret_in_peer_relation(
                private_key=ca_private_key, certificate=ca_certificate
            )
        if not self._ca_certificate_pushed_to_workload():
            ca_private_key, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
            self._push_ca_certificate_to_workload(certificate=ca_certificate)
        if not self._unit_certificate_pushed_to_workload():
            ca_private_key, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
            sans_ip = [self._ingress_address]
            private_key, certificate = generate_vault_unit_certificate(
                subject=self._ingress_address,
                sans_ip=sans_ip,
                sans_dns=[socket.getfqdn()],
                ca_certificate=ca_certificate.encode(),
                ca_private_key=ca_private_key.encode(),
            )
            self._push_unit_certificate_to_workload(
                certificate=certificate, private_key=private_key
            )
        self._generate_vault_config_file()
        self._set_pebble_plan()
        vault = Vault(url=self._api_address, ca_cert_path=self._get_ca_cert_location_in_charm())
        if not vault.is_api_available():
            self.unit.status = WaitingStatus("Waiting for vault to be available")
            return
        if self.unit.is_leader() and not vault.is_initialized():
            root_token, unseal_keys = vault.initialize()
            self._set_initialization_secret_in_peer_relation(root_token, unseal_keys)
        root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
        vault.set_token(token=root_token)
        if vault.is_sealed():
            vault.unseal(unseal_keys=unseal_keys)
        if vault.is_active() and not vault.audit_device_enabled(device_type="file", path="stdout"):
            vault.enable_audit_device(device_type="file", path="stdout")
        self._set_peer_relation_node_api_address()
        self._send_ca_cert()
        self.unit.status = ActiveStatus()

    def _on_remove(self, event: RemoveEvent):
        """Handler triggered when the charm is removed.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        if not self._container.can_connect():
            return
        try:
            root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
            if self._bind_address:
                vault = Vault(
                    url=self._api_address, ca_cert_path=self._get_ca_cert_location_in_charm()
                )
                vault.set_token(token=root_token)
                if (
                    vault.is_api_available()
                    and vault.is_node_in_raft_peers(node_id=self._node_id)
                    and vault.get_num_raft_peers() > 1
                ):
                    vault.remove_raft_node(node_id=self._node_id)
        except PeerSecretError:
            logger.info("Vault initialization secret not set in peer relation")
        except VaultCertsError:
            logger.info("Vault CA certificate not found")
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
            _, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
        except PeerSecretError:
            logger.debug("Vault CA certificate secret not set in peer relation, deferring event")
            event.defer()
            return

        relation = self.model.get_relation(event.relation_name, event.relation_id)

        if relation is None or relation.app is None:
            logger.warning(
                "Relation or remote application is missing,"
                "this should not happen, skipping event"
            )
            return

        vault = Vault(url=self._api_address, ca_cert_path=self._get_ca_cert_location_in_charm())
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

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handles create-backup action.

        Creates a snapshot and stores it on S3 storage.
        Outputs the ID of the backup to the user.

        Args:
            event: ActionEvent
        """
        if not self.unit.is_leader():
            logger.error("Only leader unit can perform backup operations.")
            event.fail(message="Only leader unit can perform backup operations.")
            return

        s3_requirements, error_message = self._check_s3_requirements()
        if not s3_requirements:
            logger.error(error_message)
            event.fail(message=f"{error_message} Failed to perform backup.")
            return

        s3_parameters = self._retrieve_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except (BotoCoreError, ClientError, ValueError) as e:
            logger.error("Failed to create S3 session: %s", e)
            event.fail(message="Failed to create S3 session.")
            return

        try:
            if not (s3.create_bucket(bucket_name=s3_parameters["bucket"])):
                logger.error("Failed to create S3 bucket")
                event.fail(message="Failed to create S3 bucket.")
                return
        except ConnectTimeoutError as e:
            logger.error("Failed to create S3 bucket: %s", e)
            event.fail(message="Timeout trying to connect to S3 endpoint.")
            return

        snapshot = self._create_raft_snapshot()
        if not snapshot:
            logger.error("Failed to create raft snapshot")
            event.fail(message="Failed to create raft snapshot.")
            return
        backup_key = self._get_backup_key()
        try:
            content_uploaded = s3.upload_content(
                content=snapshot,
                bucket_name=s3_parameters["bucket"],
                key=backup_key,
            )
        except ConnectTimeoutError as e:
            logger.error("Failed to upload backup to S3 bucket: %s", e)
            event.fail(message="Timeout trying to connect to S3 endpoint.")
            return

        if not content_uploaded:
            logger.error("Failed to upload backup to S3 bucket")
            event.fail(message="Failed to upload backup to S3 bucket.")
            return
        logger.info("Backup uploaded to S3 bucket %s", s3_parameters["bucket"])
        event.set_results({"backup-id": backup_key})

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handles list-backups action.

        Lists all backups stored in S3 bucket.

        Args:
            event: ActionEvent
        """
        if not self.unit.is_leader():
            logger.error("Only leader unit can list backups.")
            event.fail(message="Only leader unit can list backups.")
            return

        s3_requirements, error_message = self._check_s3_requirements()
        if not s3_requirements:
            logger.error(error_message)
            event.fail(message=f"{error_message} Failed to list backups.")
            return

        s3_parameters = self._retrieve_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except (BotoCoreError, ClientError, ValueError) as e:
            logger.error("Failed to create S3 session: %s", e)
            event.fail(message="Failed to create S3 session.")
            return

        try:
            backup_ids = s3.get_object_key_list(
                bucket_name=s3_parameters["bucket"], prefix=BACKUP_KEY_PREFIX
            )
        except ConnectTimeoutError as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message="Timeout trying to connect to S3 endpoint.")
            return
        except (BotoCoreError, ClientError) as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message="Failed to list backups.")
            return
        event.set_results({"backup-ids": backup_ids})

    def _on_restore_backup_action(self, event: ActionEvent) -> None:
        """Handles restore-backup action.

        Restores the snapshot with the provided ID.
        Unseals Vault using the provided unseal key.
        Sets the root token to the provided root token.
        Updates the initialization secret in the peer relation
            with the provided unseal key and root token.

        Args:
            event: ActionEvent
        """
        if not self.unit.is_leader():
            logger.error("Only leader unit can restore backups.")
            event.fail(message="Only leader unit can restore backups.")
            return

        s3_requirements, error_message = self._check_s3_requirements()
        if not s3_requirements:
            logger.error(error_message)
            event.fail(message=f"{error_message} Failed to restore backup.")
            return

        s3_parameters = self._retrieve_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except (BotoCoreError, ClientError, ValueError) as e:
            logger.error("Failed to create S3 session: %s", e)
            event.fail(message="Failed to create S3 session.")
            return

        try:
            snapshot = s3.get_content(
                bucket_name=s3_parameters["bucket"], object_key=event.params.get("backup-id")  # type: ignore[arg-type]
            )
        except ConnectTimeoutError as e:
            logger.error("Failed to retrieve snapshot from S3 storage: %s", e)
            event.fail(message="Timeout trying to connect to S3 endpoint.")
            return
        except (BotoCoreError, ClientError) as e:
            logger.error("Failed to retrieve snapshot from S3 storage: %s", e)
            event.fail(message="Failed to retrieve snapshot from S3 storage.")
            return
        if not snapshot:
            logger.error("Backup %s not found in S3 bucket", event.params.get("backup-id"))
            event.fail(message="Backup not found in S3 bucket.")
            return
        try:
            if not (
                self._restore_vault(
                    snapshot=snapshot,
                    restore_unseal_keys=event.params.get("unseal-keys"),  # type: ignore[arg-type]
                    restore_root_token=event.params.get("root-token"),  # type: ignore[arg-type]
                )
            ):
                logger.error("Failed to restore vault.")
                event.fail(message="Failed to restore vault.")
                return
        except RuntimeError as e:
            logger.error("Failed to restore vault: %s", e)
            event.fail(message="Failed to restore vault.")
            return
        event.set_results({"restored": event.params.get("backup-id")})

    def _check_s3_requirements(self) -> Tuple[bool, Optional[str]]:
        """Validates the requirements for creating S3.

        It will check if the S3 relation is created
            and if the required S3 parameters are set.

        Returns:
            bool: True if the requirements are met, False otherwise.
        """
        if not self._is_relation_created(S3_RELATION_NAME):
            return False, "S3 relation not created."

        missing_parameters = self._get_missing_s3_parameters()
        if missing_parameters:
            return False, f"S3 parameters missing. {missing_parameters}"

        return True, None

    def _get_backup_key(self) -> str:
        """Returns the backup key.

        Returns:
            str: The backup key
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return f"{BACKUP_KEY_PREFIX}-{self.model.name}-{timestamp}"

    def _get_ca_cert_location_in_charm(self) -> str:
        """Returns the CA certificate location in the charm (not in the workload).

        This path would typically be: /var/lib/juju/storage/certs/0/ca.pem

        Returns:
            str: Path

        Raises:
            VaultCertsError: If the CA certificate is not found
        """
        storage = self.model.storages
        if "certs" not in storage:
            raise VaultCertsError()
        if len(storage["certs"]) == 0:
            raise VaultCertsError()
        cert_storage = storage["certs"][0]
        storage_location = cert_storage.location
        return f"{storage_location}/ca.pem"

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
        """Returns the FQDN with the https schema and vault port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8200"
        """
        return f"https://{socket.getfqdn()}:{self.VAULT_PORT}"

    @property
    def _cluster_address(self) -> str:
        """Returns the FQDN with the https schema and vault cluster port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8201"
        """
        return f"https://{socket.getfqdn()}:{self.VAULT_CLUSTER_PORT}"

    def _push_ca_certificate_to_workload(self, certificate: str) -> None:
        """Push the CA certificate to the workload.

        Args:
            certificate: CA certificate
        """
        self._container.push(path=TLS_CA_FILE_PATH, source=certificate)
        logger.info("Pushed CA certificate to workload")

    def _push_unit_certificate_to_workload(self, private_key: str, certificate: str) -> None:
        """Push the unit certificate to the workload.

        Args:
            private_key: Private key
            certificate: Certificate
        """
        self._container.push(path=TLS_KEY_FILE_PATH, source=private_key)
        self._container.push(path=TLS_CERT_FILE_PATH, source=certificate)
        logger.info("Pushed unit certificate to workload")

    def _ca_certificate_pushed_to_workload(self) -> bool:
        """Returns whether CA certificate is pushed to the workload."""
        return self._container.exists(path=TLS_CA_FILE_PATH)

    def _unit_certificate_pushed_to_workload(self) -> bool:
        """Returns whether unit certificate is pushed to the workload."""
        return self._container.exists(path=TLS_KEY_FILE_PATH) and self._container.exists(
            path=TLS_CERT_FILE_PATH
        )

    def _generate_vault_config_file(self) -> None:
        """Handles creation of the Vault config file."""
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": TLS_CA_FILE_PATH,
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]
        content = render_vault_config_file(
            default_lease_ttl=self.model.config["default_lease_ttl"],
            max_lease_ttl=self.model.config["max_lease_ttl"],
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tcp_address=f"[::]:{self.VAULT_PORT}",
            tls_cert_file=TLS_CERT_FILE_PATH,
            tls_key_file=TLS_KEY_FILE_PATH,
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
        )
        existing_content = ""
        if self._container.exists(path=VAULT_CONFIG_FILE_PATH):
            existing_content_stringio = self._container.pull(path=VAULT_CONFIG_FILE_PATH)
            existing_content = existing_content_stringio.read()

        if not config_file_content_matches(existing_content=existing_content, new_content=content):
            self._push_config_file_to_workload(content=content)

    def _push_config_file_to_workload(self, content: str):
        """Push the config file to the workload."""
        self._container.push(path=VAULT_CONFIG_FILE_PATH, source=content)
        logger.info("Pushed %s config file", VAULT_CONFIG_FILE_PATH)

    def _set_ca_certificate_secret_in_peer_relation(
        self,
        private_key: str,
        certificate: str,
    ) -> None:
        """Set the vault CA certificate secret in the peer relation.

        Args:
            private_key: Private key
            certificate: certificate
        """
        if not self._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        juju_secret_content = {
            "privatekey": private_key,
            "certificate": certificate,
        }
        juju_secret = self.app.add_secret(
            juju_secret_content, label=CA_CERTIFICATE_JUJU_SECRET_LABEL
        )
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        peer_relation.data[self.app].update({CA_CERTIFICATE_JUJU_SECRET_KEY: juju_secret.id})  # type: ignore[union-attr]  # noqa: E501
        logger.info("Vault CA certificate secret set in peer relation")

    def _get_ca_certificate_secret_in_peer_relation(self) -> Tuple[str, str]:
        """Get the vault CA certificate secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[str]]: The CA private key and certificate
        """
        try:
            peer_relation = self.model.get_relation(PEER_RELATION_NAME)
            juju_secret_id = peer_relation.data[peer_relation.app].get(  # type: ignore[union-attr, index]  # noqa: E501
                CA_CERTIFICATE_JUJU_SECRET_KEY
            )
            juju_secret = self.model.get_secret(id=juju_secret_id)
            content = juju_secret.get_content()
            return content["privatekey"], content["certificate"]
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name=CA_CERTIFICATE_JUJU_SECRET_KEY)

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
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not self._initialization_secret_set_in_peer_relation():
            juju_secret = self.app.add_secret(
                juju_secret_content, label=VAULT_INITIALIZATION_SECRET_LABEL
            )
            peer_relation.data[self.app].update({"vault-initialization-secret-id": juju_secret.id})  # type: ignore[union-attr]  # noqa: E501
            return
        secret = self.model.get_secret(label=VAULT_INITIALIZATION_SECRET_LABEL)
        secret.set_content(content=juju_secret_content)
        peer_relation.data[self.app].update({"vault-initialization-secret-id": secret.id})  # type: ignore[union-attr]

    def _get_initialization_secret_from_peer_relation(self) -> Tuple[str, List[str]]:
        """Get the vault initialization secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[List[str]]]: The root token and unseal keys.
        """
        try:
            juju_secret = self.model.get_secret(label=VAULT_INITIALIZATION_SECRET_LABEL)
            content = juju_secret.get_content()
            return content["roottoken"], json.loads(content["unsealkeys"])
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name=VAULT_INITIALIZATION_SECRET_LABEL)

    def _get_missing_s3_parameters(self) -> List[str]:
        """Returns list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        return [param for param in REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _retrieve_s3_parameters(self) -> Dict[str, str]:
        """Retrieve S3 parameters from the S3 integrator relation.

        Removes leading and trailing whitespaces from the parameters.

        Returns:
            Dict[str, str]: Dictionary of the S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        for key, value in s3_parameters.items():
            if isinstance(value, str):
                s3_parameters[key] = value.strip()

        return s3_parameters

    def _is_peer_relation_created(self) -> bool:
        """Check if the peer relation is created."""
        return bool(self.model.get_relation(PEER_RELATION_NAME))

    def _is_relation_created(self, relation_name: str) -> bool:
        """Check if the relation is created.

        Args:
            relation_name: Checked relation name
        """
        return bool(self.model.get_relation(relation_name))

    def _set_pebble_plan(self) -> None:
        """Set the pebble plan if different from the currently applied one."""
        plan = self._container.get_plan()
        layer = self._vault_layer
        if plan.services != layer.services:
            self._container.add_layer(self._container_name, layer, combine=True)
            self._container.replan()
            logger.info("Pebble layer added")

    def _on_send_ca_cert_relation_joined(self, event: RelationJoinedEvent):
        """Send Vault CA certificate when relation joined.

        Args:
            event: RelationJoinedEvent
        """
        self._send_ca_cert(rel_id=event.relation.id)

    def _send_ca_cert(self, *, rel_id=None) -> None:
        """There is one (and only one) CA cert that we need to forward to multiple apps.

        Args:
            rel_id: Relation id. If not given, update all relations.
        """
        send_ca_cert = CertificateTransferProvides(self, SEND_CA_CERT_RELATION_NAME)
        if self._ca_certificate_set_in_peer_relation():
            secret = self.model.get_secret(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            secret_content = secret.get_content()
            ca = secret_content["certificate"]
            if rel_id:
                send_ca_cert.set_certificate(certificate="", ca=ca, chain=[], relation_id=rel_id)
            else:
                for relation in self.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                    send_ca_cert.set_certificate(
                        certificate="", ca=ca, chain=[], relation_id=relation.id
                    )
        else:
            for relation in self.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                send_ca_cert.remove_certificate(relation.id)

    def _ca_certificate_set_in_peer_relation(self) -> bool:
        """Returns whether CA certificate is stored in peer relation data."""
        try:
            ca_private_key, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
            if ca_private_key and ca_certificate:
                return True
        except PeerSecretError:
            return False
        return False

    def _initialization_secret_set_in_peer_relation(self) -> bool:
        """Returns whether initialization secret is stored in peer relation data."""
        try:
            root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
            if root_token and unseal_keys:
                return True
        except PeerSecretError:
            return False
        return False

    def _create_raft_snapshot(self) -> Optional[IO[bytes]]:
        """Creates a snapshot of Vault.

        Returns:
            IO[bytes]: The snapshot content as a file like object.
        """
        if not (vault := self._get_initialized_vault_client()):
            logger.error("Failed to get Vault client, cannot create snapshot.")
            return None
        root_token, unseal_keys = self._get_initialization_secret_from_peer_relation()
        vault.set_token(token=root_token)
        if vault.is_sealed():
            vault.unseal(unseal_keys=unseal_keys)
        response = vault.create_snapshot()
        return response.raw

    def _restore_vault(
        self, snapshot: StreamingBody, restore_unseal_keys: List[str], restore_root_token: str
    ) -> bool:
        """Restore vault using a raft snapshot.

        Updates the initialization secret in the peer relation.
        Upon successful secret update, it will restore the raft snapshot.
        Upon successful restore, it will unseal Vault and set root token.

        Args:
            snapshot: Snapshot to be restored as a StreamingBody from the S3 storage.
            restore_unseal_keys: List of unseal keys used at the time of the backup.
            restore_root_token: Root token used at the time of the backup.

        Returns:
            bool: True if the restore was successful, False otherwise.
        """
        if not (vault := self._get_initialized_vault_client()):
            logger.error("Failed to get Vault client, cannot restore snapshot.")
            return False
        (
            current_root_token,
            current_unseal_keys,
        ) = self._get_initialization_secret_from_peer_relation()
        vault.set_token(token=current_root_token)
        if vault.is_sealed():
            vault.unseal(unseal_keys=current_unseal_keys)

        self._set_initialization_secret_in_peer_relation(
            root_token=restore_root_token, unseal_keys=restore_unseal_keys
        )
        try:
            # hvac vault client expects bytes or a file-like object to restore the snapshot
            # StreamingBody implements the read() method
            # so it can be used as a file-like object in this context
            response = vault.restore_snapshot(snapshot)  # type: ignore[arg-type]
        except Exception as e:
            # If restore fails for any reason, we reset the initialization secret
            logger.error("Failed to restore snapshot: %s", e)
            self._set_initialization_secret_in_peer_relation(
                root_token=current_root_token, unseal_keys=current_unseal_keys
            )
            return False
        if not 200 <= response.status_code < 300:
            logger.error("Failed to restore snapshot: %s", response.json())
            self._set_initialization_secret_in_peer_relation(
                root_token=current_root_token, unseal_keys=current_unseal_keys
            )
            return False
        vault.set_token(token=restore_root_token)
        if vault.is_sealed():
            vault.unseal(unseal_keys=restore_unseal_keys)
        return True

    def _get_initialized_vault_client(self) -> Optional[Vault]:
        """Returns an initialized vault client.

        Creates a Vault client and returns it if:
            - Vault is initialized
            - Vault API is available
            - Vault is unsealed
        Otherwise, returns None.

        Returns:
            Vault: Vault client
        """
        vault = Vault(url=self._api_address, ca_cert_path=self._get_ca_cert_location_in_charm())
        if not vault.is_initialized():
            logger.error("Vault is not initialized.")
            return None
        if not vault.is_api_available():
            logger.error("Vault API is not available.")
            return None
        try:
            self._get_initialization_secret_from_peer_relation()
        except PeerSecretError:
            logger.error("Vault initialization secret not set in peer relation.")
            return None
        return vault

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
            if not binding or not binding.network.bind_address:
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
            if not binding or not binding.network.ingress_address:
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
