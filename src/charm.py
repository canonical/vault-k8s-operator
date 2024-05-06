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
from typing import IO, Dict, List, Optional, Tuple, cast

import hcl
from botocore.response import StreamingBody
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV3,
    TLSCertificatesRequiresV3,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    Vault,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_kv import NewVaultKvClientAttachedEvent, VaultKvProvides
from charms.vault_k8s.v0.vault_s3 import S3, S3Error
from charms.vault_k8s.v0.vault_tls import File, VaultCertsError, VaultTLSManager
from container import Container
from cryptography import x509
from jinja2 import Environment, FileSystemLoader
from ops.charm import (
    ActionEvent,
    CharmBase,
    CollectStatusEvent,
    ConfigChangedEvent,
    InstallEvent,
    RelationJoinedEvent,
    RemoveEvent,
)
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    ModelError,
    Relation,
    Secret,
    SecretNotFoundError,
    WaitingStatus,
)
from ops.pebble import ChangeError, Layer, PathError

logger = logging.getLogger(__name__)

VAULT_STORAGE_PATH = "/vault/raft"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
VAULT_CONFIG_FILE_PATH = "/vault/config/vault.hcl"
PEER_RELATION_NAME = "vault-peers"
KV_RELATION_NAME = "vault-kv"
PKI_RELATION_NAME = "vault-pki"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
KV_SECRET_PREFIX = "kv-creds-"
LOG_FORWARDING_RELATION_NAME = "logging"
PKI_CSR_SECRET_LABEL = "pki-csr"
S3_RELATION_NAME = "s3-parameters"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
BACKUP_KEY_PREFIX = "vault-backup"
CONTAINER_TLS_FILE_DIRECTORY_PATH = "/vault/certs"
CONTAINER_NAME = "vault"
PKI_MOUNT = "charm-pki"
PKI_ROLE = "charm"
CHARM_POLICY_NAME = "charm-access"
CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"


class VaultCharm(CharmBase):
    """Main class for to handle Juju events for the vault-k8s charm."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args):
        super().__init__(*args)
        self._service_name = self._container_name = CONTAINER_NAME
        self._container = Container(container=self.unit.get_container(self._container_name))
        self.service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="vault", port=self.VAULT_PORT)],
        )
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV3(self, PKI_RELATION_NAME)
        self.tls_certificates_pki = TLSCertificatesRequiresV3(
            self, TLS_CERTIFICATES_PKI_RELATION_NAME
        )
        self.grafana_dashboards = GrafanaDashboardProvider(self)
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
        self._logging = LogForwarder(charm=self, relation_name=LOG_FORWARDING_RELATION_NAME)
        self.tls = VaultTLSManager(
            charm=self,
            workload=self._container,
            service_name=self._container_name,
            tls_directory_path=CONTAINER_TLS_FILE_DIRECTORY_PATH,
        )
        self.ingress = IngressPerAppRequirer(
            charm=self,
            port=self.VAULT_PORT,
            strip_prefix=True,
            scheme=lambda: "https",
        )
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.vault_pebble_ready, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_created, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_changed, self._configure)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)
        self.framework.observe(self.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.on.restore_backup_action, self._on_restore_backup_action)
        self.framework.observe(
            self.vault_kv.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )
        self.framework.observe(
            self.on.tls_certificates_pki_relation_joined,
            self._on_tls_certificates_pki_relation_joined,
        )
        self.framework.observe(
            self.tls_certificates_pki.on.certificate_available,
            self._on_tls_certificate_pki_certificate_available,
        )
        self.framework.observe(
            self.vault_pki.on.certificate_creation_request,
            self._on_vault_pki_certificate_creation_request,
        )

    def _on_install(self, event: InstallEvent):
        """Handle the install charm event."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_vault_data()

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa: C901
        """Handle the collect status event."""
        if (
            self._tls_certificates_pki_relation_created()
            and not self._common_name_config_is_valid()
        ):
            event.add_status(
                BlockedStatus(
                    "Common name is not set in the charm config, cannot configure PKI secrets engine"
                )
            )
            return
        if not self._container.can_connect():
            event.add_status(WaitingStatus("Waiting to be able to connect to vault unit"))
            return
        if not self._is_peer_relation_created():
            event.add_status(WaitingStatus("Waiting for peer relation"))
            return
        if not self._bind_address or not self._ingress_address:
            event.add_status(
                WaitingStatus("Waiting for bind and ingress addresses to be available")
            )
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.add_status(
                WaitingStatus("Waiting for CA certificate to be accessible in the charm")
            )
            return
        if not self.unit.is_leader() and not self.tls.ca_certificate_secret_exists():
            event.add_status(WaitingStatus("Waiting for CA certificate secret"))
            return
        if not self.unit.is_leader() and not self.tls.tls_file_pushed_to_workload(File.CA):
            event.add_status(WaitingStatus("Waiting for CA certificate to be shared"))
            return
        vault = Vault(
            url=self._api_address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA)
        )
        if not vault.is_api_available():
            event.add_status(WaitingStatus("Waiting for vault to be available"))
            return
        if not vault.is_initialized():
            event.add_status(BlockedStatus("Please initialize Vault"))
            return
        if vault.is_sealed():
            event.add_status(BlockedStatus("Please unseal Vault"))
            return
        role_id, secret_id = self._get_approle_auth_secret()
        if not role_id or not secret_id:
            event.add_status(
                BlockedStatus("Please authorize charm (see `authorize-charm` action)")
            )
            return
        if not self._get_active_vault_client():
            event.add_status(WaitingStatus("Waiting for vault to finish raft leader election"))
        event.add_status(ActiveStatus())

    def _configure(self, event: Optional[ConfigChangedEvent] = None) -> None:  # noqa: C901
        """Handle config-changed event.

        Configures pebble layer, sets the unit address in the peer relation, starts the vault
        service, and unseals Vault.
        """
        if not self._container.can_connect():
            return
        if not self._is_peer_relation_created():
            return
        if not self._bind_address or not self._ingress_address:
            return
        try:
            self.tls.get_tls_file_path_in_charm(File.CA)
        except VaultCertsError:
            return
        if not self.unit.is_leader() and not self.tls.ca_certificate_secret_exists():
            return
        self.tls.configure_certificates(self._ingress_address)
        if not self.unit.is_leader() and not self.tls.tls_file_pushed_to_workload(File.CA):
            return

        self._generate_vault_config_file()
        self._set_pebble_plan()
        vault = Vault(
            url=self._api_address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA)
        )
        if not vault.is_api_available():
            return
        if not vault.is_initialized():
            return
        if vault.is_sealed():
            return
        if not all(self._get_approle_auth_secret()):
            return
        if not (vault := self._get_active_vault_client()):
            return
        self._configure_pki_secrets_engine()
        self._add_ca_certificate_to_pki_secrets_engine()
        self._sync_vault_kv()
        self._sync_vault_pki()
        self.tls.send_ca_cert()
        if vault.is_active_or_standby() and not vault.is_raft_cluster_healthy():
            # Log if a raft node starts reporting unhealthy
            logger.error(
                "Raft cluster is not healthy. %s",
                vault.get_raft_cluster_state(),
            )

    def _on_remove(self, event: RemoveEvent):
        """Handle remove charm event.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        if not self._container.can_connect():
            return
        self._remove_node_from_raft_cluster()
        if self._vault_service_is_running():
            try:
                self._container.stop(self._service_name)
            except ChangeError:
                logger.warning("Failed to stop Vault service")
                pass
        self._delete_vault_data()

    def _remove_node_from_raft_cluster(self):
        """Remove the node from the raft cluster."""
        role_id, secret_id = self._get_approle_auth_secret()
        if not role_id or not secret_id:
            return
        vault = Vault(url=self._api_address, ca_cert_path=None)
        if not vault.is_api_available():
            return
        if not vault.is_initialized():
            return
        if vault.is_sealed():
            return
        vault.authenticate(AppRole(role_id, secret_id))
        if vault.is_node_in_raft_peers(node_id=self._node_id) and vault.get_num_raft_peers() > 1:
            vault.remove_raft_node(node_id=self._node_id)

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
        """Handle vault-kv-client attached event."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        relation = self.model.get_relation(
            relation_name=KV_RELATION_NAME, relation_id=event.relation_id
        )
        if not relation:
            logger.error("Relation not found for relation id %s", event.relation_id)
            return
        if not relation.active:
            logger.error("Relation is not active for relation id %s", event.relation_id)
            return
        self._generate_kv_for_requirer(
            relation=relation,
            app_name=event.app_name,
            unit_name=event.unit_name,
            mount_suffix=event.mount_suffix,
            egress_subnet=event.egress_subnet,
            nonce=event.nonce,
        )

    def _on_tls_certificates_pki_relation_joined(self, _: RelationJoinedEvent) -> None:
        """Handle the tls-certificates-pki relation joined event."""
        self._configure_pki_secrets_engine()

    def _configure_pki_secrets_engine(self) -> None:
        """Configure the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        if not self._tls_certificates_pki_relation_created():
            logger.debug("TLS Certificates PKI relation not created, skipping")
            return
        if not self._common_name_config_is_valid():
            logger.debug("Common name config is not valid, skipping")
            return
        common_name = self._get_config_common_name()
        vault.enable_secrets_engine(SecretsBackend.PKI, PKI_MOUNT)
        if not self._is_intermediate_ca_set(vault, common_name):
            csr = vault.generate_pki_intermediate_ca_csr(mount=PKI_MOUNT, common_name=common_name)
            self.tls_certificates_pki.request_certificate_creation(
                certificate_signing_request=csr.encode(),
                is_ca=True,
            )
            self._set_pki_csr_secret(csr)

    def _is_intermediate_ca_set(self, vault: Vault, common_name: str) -> bool:
        """Check if the intermediate CA is set in the PKI secrets engine."""
        intermediate_ca = vault.get_intermediate_ca(mount=PKI_MOUNT)
        if not intermediate_ca:
            return False
        intermediate_ca_common_name = get_common_name_from_certificate(intermediate_ca)
        return intermediate_ca_common_name == common_name

    def _add_ca_certificate_to_pki_secrets_engine(self) -> None:
        """Add the CA certificate to the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        common_name = self._get_config_common_name()
        if not common_name:
            logger.error("Common name is not set in the charm config")
            return
        certificate = self._get_pki_ca_certificate()
        if not certificate:
            logger.debug("No certificate available")
            return
        if not vault.is_intermediate_ca_set(mount=PKI_MOUNT, certificate=certificate):
            vault.set_pki_intermediate_ca_certificate(certificate=certificate, mount=PKI_MOUNT)
        if not vault.is_pki_role_created(role=PKI_ROLE, mount=PKI_MOUNT):
            vault.create_pki_charm_role(
                allowed_domains=common_name,
                mount=PKI_MOUNT,
                role=PKI_ROLE,
            )

    def _sync_vault_pki(self) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        outstanding_pki_requests = self.vault_pki.get_outstanding_certificate_requests()
        for pki_request in outstanding_pki_requests:
            self._generate_pki_certificate_for_requirer(
                csr=pki_request.csr,
                relation_id=pki_request.relation_id,
            )

    def _sync_vault_kv(self) -> None:
        """Goes through all the vault-kv relations and sends necessary KV information."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        outstanding_kv_requests = self.vault_kv.get_outstanding_kv_requests()
        for kv_request in outstanding_kv_requests:
            relation = self.model.get_relation(
                relation_name=KV_RELATION_NAME, relation_id=kv_request.relation_id
            )
            if not relation:
                logger.warning("Relation not found for relation id %s", kv_request.relation_id)
                continue
            if not relation.active:
                logger.warning("Relation is not active for relation id %s", kv_request.relation_id)
                continue
            self._generate_kv_for_requirer(
                relation=relation,
                app_name=kv_request.app_name,
                unit_name=kv_request.unit_name,
                mount_suffix=kv_request.mount_suffix,
                egress_subnet=kv_request.egress_subnet,
                nonce=kv_request.nonce,
            )

    def _generate_kv_for_requirer(
        self,
        relation: Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnet: str,
        nonce: str,
    ):
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        ca_certificate = self.tls.pull_tls_file_from_workload(File.CA)
        if not ca_certificate:
            logger.debug("Vault CA certificate not available")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        mount = f"charm-{app_name}-{mount_suffix}"
        self._set_kv_relation_data(relation, mount, ca_certificate)
        vault.enable_secrets_engine(SecretsBackend.KV_V2, mount)
        self._ensure_unit_credentials(vault, relation, unit_name, mount, nonce, egress_subnet)
        self._remove_stale_nonce(relation=relation, nonce=nonce)

    def _get_pki_ca_certificate(self) -> Optional[str]:
        """Return the PKI CA certificate provided by the TLS provider.

        Validate that the CSR matches the one in secrets.
        """
        assigned_certificates = self.tls_certificates_pki.get_assigned_certificates()
        if not assigned_certificates:
            return None
        if not self._pki_csr_secret_set():
            logger.info("PKI CSR not set in secrets")
            return None
        pki_csr = self._get_pki_csr_secret()
        if not pki_csr:
            logger.warning("PKI CSR not found in secrets")
            return None
        for assigned_certificate in assigned_certificates:
            if assigned_certificate.csr == pki_csr:
                return assigned_certificate.certificate
        logger.info("No certificate matches the PKI CSR in secrets")
        return None

    def _on_tls_certificate_pki_certificate_available(self, event: CertificateAvailableEvent):
        """Handle the tls-certificates-pki certificate available event."""
        self._add_ca_certificate_to_pki_secrets_engine()

    def _on_vault_pki_certificate_creation_request(
        self, event: CertificateCreationRequestEvent
    ) -> None:
        """Handle the vault-pki certificate creation request event."""
        self._generate_pki_certificate_for_requirer(
            event.certificate_signing_request, event.relation_id
        )

    def _generate_pki_certificate_for_requirer(self, csr: str, relation_id: int):
        """Generate a PKI certificate for a TLS requirer."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        if not self._tls_certificates_pki_relation_created():
            logger.debug("TLS Certificates PKI relation not created")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        common_name = self._get_config_common_name()
        if not common_name:
            logger.error("Common name is not set in the charm config")
            return
        if not vault.is_pki_role_created(role=PKI_ROLE, mount=PKI_MOUNT):
            logger.debug("PKI role not created")
            return
        requested_csr = csr
        requested_common_name = get_common_name_from_csr(requested_csr)
        certificate = vault.sign_pki_certificate_signing_request(
            mount=PKI_MOUNT,
            role=PKI_ROLE,
            csr=requested_csr,
            common_name=requested_common_name,
        )
        if not certificate:
            logger.debug("Failed to sign the certificate")
            return
        self.vault_pki.set_relation_certificate(
            relation_id=relation_id,
            certificate=certificate.certificate,
            certificate_signing_request=csr,
            ca=certificate.ca,
            chain=certificate.chain,
        )

    def _on_authorize_charm_action(self, event: ActionEvent) -> None:
        if not self.unit.is_leader():
            event.fail("This action must be run on the leader unit.")
            return

        token = event.params.get("token", "")
        vault = Vault(self._api_address, self.tls.get_tls_file_path_in_charm(File.CA))
        vault.authenticate(Token(token))

        if not vault.get_token_data():
            event.fail("The token provided is not valid.")
            return

        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.configure_policy(policy_name=CHARM_POLICY_NAME, policy_path=CHARM_POLICY_PATH)
            cidrs = [f"{self._bind_address}/24"]
            role_id = vault.configure_approle(
                role_name="charm",
                cidrs=cidrs,
                policies=[CHARM_POLICY_NAME, "default"],
            )
            secret_id = vault.generate_role_secret_id(name="charm", cidrs=cidrs)
            self._set_approle_auth_secret(role_id, secret_id)
            event.set_results({"result": "Charm authorized successfully."})
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")
            return

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handle the create-backup action.

        Creates a snapshot and stores it on S3 storage.
        Outputs the ID of the backup to the user.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error:
            event.fail(message="Failed to create S3 session.")
            logger.error("Failed to run create-backup action - Failed to create S3 session.")
            return

        if not (s3.create_bucket(bucket_name=s3_parameters["bucket"])):
            event.fail(message="Failed to create S3 bucket.")
            logger.error("Failed to run create-backup action - Failed to create S3 bucket.")
            return
        backup_key = self._get_backup_key()
        vault = self._get_active_vault_client()
        if not vault:
            event.fail(message="Failed to initialize Vault client.")
            logger.error("Failed to run create-backup action - Failed to initialize Vault client.")
            return

        response = vault.create_snapshot()
        content_uploaded = s3.upload_content(
            content=response.raw,
            bucket_name=s3_parameters["bucket"],
            key=backup_key,
        )
        if not content_uploaded:
            event.fail(message="Failed to upload backup to S3 bucket.")
            logger.error(
                "Failed to run create-backup action - Failed to upload backup to S3 bucket."
            )
            return
        logger.info("Backup uploaded to S3 bucket %s", s3_parameters["bucket"])
        event.set_results({"backup-id": backup_key})

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handle the list-backups action.

        Lists all backups stored in S3 bucket.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error as e:
            event.fail(message="Failed to create S3 session.")
            logger.error("Failed to run list-backups action - %s", e)
            return

        try:
            backup_ids = s3.get_object_key_list(
                bucket_name=s3_parameters["bucket"], prefix=BACKUP_KEY_PREFIX
            )
        except S3Error as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message="Failed to run list-backups action - Failed to list backups.")
            return

        event.set_results({"backup-ids": json.dumps(backup_ids)})

    def _on_restore_backup_action(self, event: ActionEvent) -> None:
        """Handle the restore-backup action.

        Restores the snapshot with the provided ID.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()
        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error as e:
            logger.error("Failed to create S3 session: %s", e)
            event.fail(message="Failed to create S3 session.")
            return
        try:
            snapshot = s3.get_content(
                bucket_name=s3_parameters["bucket"],
                object_key=event.params.get("backup-id"),  # type: ignore[reportArgumentType]
            )
        except S3Error as e:
            logger.error("Failed to retrieve snapshot from S3 storage: %s", e)
            event.fail(message="Failed to retrieve snapshot from S3 storage.")
            return
        if not snapshot:
            logger.error("Backup %s not found in S3 bucket", event.params.get("backup-id"))
            event.fail(message="Backup not found in S3 bucket.")
            return
        try:
            if not (self._restore_vault(snapshot=snapshot)):
                logger.error("Failed to restore vault.")
                event.fail(message="Failed to restore vault.")
                return
        except RuntimeError as e:
            logger.error("Failed to restore vault: %s", e)
            event.fail(message="Failed to restore vault.")
            return
        try:
            if self._approle_secret_set():
                role_id, secret_id = self._get_approle_auth_secret()
                vault = Vault(
                    url=self._api_address,
                    ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
                )
                if role_id and secret_id and not vault.authenticate(AppRole(role_id, secret_id)):
                    self._remove_approle_auth_secret()
        except Exception as e:
            logger.error("Failed to remove old approle secret: %s", e)
            event.fail(message="Failed to remove old approle secret.")

        event.set_results({"restored": event.params.get("backup-id")})

    def _get_s3_parameters(self) -> Dict[str, str]:
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

    def _check_s3_pre_requisites(self) -> Optional[str]:
        """Check if the S3 pre-requisites are met."""
        if not self.unit.is_leader():
            return "Only leader unit can perform backup operations"
        if not self._is_relation_created(S3_RELATION_NAME):
            return "S3 relation not created"
        if missing_parameters := self._get_missing_s3_parameters():
            return "S3 parameters missing ({}):".format(", ".join(missing_parameters))
        return None

    def _get_backup_key(self) -> str:
        """Return the backup key.

        Returns:
            str: The backup key
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return f"{BACKUP_KEY_PREFIX}-{self.model.name}-{timestamp}"

    def _set_kv_relation_data(self, relation: Relation, mount: str, ca_certificate: str) -> None:
        """Set relation data for vault-kv.

        Args:
            relation: Relation
            mount: mount name
            ca_certificate: CA certificate
        """
        self.vault_kv.set_mount(relation, mount)
        vault_url = self._get_relation_api_address(relation)
        self.vault_kv.set_ca_certificate(relation, ca_certificate)
        if vault_url is not None:
            self.vault_kv.set_vault_url(relation, vault_url)

    def _ensure_unit_credentials(
        self,
        vault: Vault,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnet: str,
    ):
        """Ensure a unit has credentials to access the vault-kv mount."""
        policy_name = role_name = mount + "-" + unit_name.replace("/", "-")
        vault.configure_policy(policy_name, "src/templates/kv_mount.hcl", mount)
        role_id = vault.configure_approle(role_name, [policy_name], [egress_subnet])
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
        credentials = secret.get_content(refresh=True)
        role_secret_id_data = vault.read_role_secret(role_name, credentials["role-secret-id"])
        # if unit subnet is already in cidr_list, skip
        if egress_subnet in role_secret_id_data["cidr_list"]:
            return secret
        credentials["role-secret-id"] = vault.generate_role_secret_id(role_name, [egress_subnet])
        secret.set_content(credentials)
        return secret

    def _remove_stale_nonce(self, relation: Relation, nonce: str) -> None:
        """Remove stale nonce.

        If the nonce is not present in the credentials, it is stale and should be removed.

        Args:
            relation: Relation
            nonce: the one to remove if stale
        """
        credential_nonces = self.vault_kv.get_credentials(relation).keys()
        if nonce not in set(credential_nonces):
            self.vault_kv.remove_unit_credentials(relation, nonce=nonce)

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
            return self._container.get_service(service_name=self._service_name).is_running()
        except ModelError:
            return False

    def _get_relation_api_address(self, relation: Relation) -> Optional[str]:
        """Fetch the api address from relation and returns it.

        Example: "https://10.152.183.20:8200"
        """
        binding = self.model.get_binding(relation)
        if binding is None:
            return None
        return f"https://{binding.network.ingress_address}:{self.VAULT_PORT}"

    @property
    def _api_address(self) -> str:
        """Return the FQDN with the https schema and vault port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8200"
        """
        return f"https://{socket.getfqdn()}:{self.VAULT_PORT}"

    @property
    def _cluster_address(self) -> str:
        """Return the FQDN with the https schema and vault cluster port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8201"
        """
        return f"https://{socket.getfqdn()}:{self.VAULT_CLUSTER_PORT}"

    def _generate_vault_config_file(self) -> None:
        """Handle the creation of the Vault config file."""
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",
            }
            for node_api_address in self._get_peer_node_api_addresses()
        ]
        content = render_vault_config_file(
            default_lease_ttl=cast(str, self.model.config["default_lease_ttl"]),
            max_lease_ttl=cast(str, self.model.config["max_lease_ttl"]),
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tcp_address=f"[::]:{self.VAULT_PORT}",
            tls_cert_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
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

    def _set_pki_csr_secret(self, csr: str) -> None:
        juju_secret_content = {"csr": csr}
        if not self._pki_csr_secret_set():
            self.app.add_secret(juju_secret_content, label=PKI_CSR_SECRET_LABEL)
            return
        secret = self.model.get_secret(label=PKI_CSR_SECRET_LABEL)
        secret.set_content(content=juju_secret_content)

    def _get_pki_csr_secret(self) -> Optional[str]:
        """Return the PKI CSR secret."""
        if not self._pki_csr_secret_set():
            raise RuntimeError("PKI CSR secret not set.")
        secret = self.model.get_secret(label=PKI_CSR_SECRET_LABEL)
        return secret.get_content(refresh=True)["csr"]

    def _pki_csr_secret_set(self) -> bool:
        """Return whether PKI CSR secret is stored."""
        try:
            self.model.get_secret(label=PKI_CSR_SECRET_LABEL)
            return True
        except SecretNotFoundError:
            return False

    def _get_approle_auth_secret(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the vault approle login details secret.

        Returns:
            Tuple[Optional[str], Optional[List[str]]]: The root token and unseal keys.
        """
        try:
            juju_secret = self.model.get_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
            content = juju_secret.get_content(refresh=True)
        except SecretNotFoundError:
            return None, None
        return content["role-id"], content["secret-id"]

    def _set_approle_auth_secret(self, role_id: str, secret_id: str) -> None:
        """Set the vault approle auth details secret.

        Args:
            role_id: The role id of the vault approle
            secret_id: The secret id of the vault approle
        """
        if not all(self._get_approle_auth_secret()):
            self.app.add_secret(
                content={"role-id": role_id, "secret-id": secret_id},
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                description="The authentication details for the charm's access to vault.",
            )
        else:
            secret = self.model.get_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
            secret.set_content({"role-id": role_id, "secret-id": secret_id})

    def _remove_approle_auth_secret(self) -> None:
        """Remove the approle secret if it exists."""
        try:
            juju_secret = self.model.get_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
            juju_secret.remove_all_revisions()
        except SecretNotFoundError:
            return

    def _get_missing_s3_parameters(self) -> List[str]:
        """Return the list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        return [param for param in REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _is_peer_relation_created(self) -> bool:
        """Check if the peer relation is created."""
        return bool(self.model.get_relation(PEER_RELATION_NAME))

    def _tls_certificates_pki_relation_created(self) -> bool:
        """Check if the TLS Certificates PKI relation is created."""
        return self._is_relation_created(TLS_CERTIFICATES_PKI_RELATION_NAME)

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

    def _approle_secret_set(self) -> bool:
        """Return whether approle secret is stored."""
        try:
            role_id, secret_id = self._get_approle_auth_secret()
            if role_id and secret_id:
                return True
        except SecretNotFoundError:
            return False
        return False

    def _create_raft_snapshot(self) -> Optional[IO[bytes]]:
        """Create a snapshot of Vault.

        Returns:
            IO[bytes]: The snapshot content as a file like object.
        """
        if not (vault := self._get_active_vault_client()):
            logger.error("Failed to get Vault client, cannot create snapshot.")
            return None
        response = vault.create_snapshot()
        return response.raw

    def _restore_vault(self, snapshot: StreamingBody) -> bool:
        """Restore vault using a raft snapshot.

        Args:
            snapshot: Snapshot to be restored as a StreamingBody from the S3 storage.

        Returns:
            bool: True if the restore was successful, False otherwise.
        """
        for address in self._get_peer_node_api_addresses():
            vault = Vault(address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA))
            if vault.is_active():
                break
        else:
            logger.error("Failed to find active Vault client, cannot restore snapshot.")
            return False
        try:
            role_id, secret_id = self._get_approle_auth_secret()
            if not role_id or not secret_id:
                logger.error("Failed to log in to Vault")
                return False
            vault.authenticate(AppRole(role_id, secret_id))
            # hvac vault client expects bytes or a file-like object to restore the snapshot
            # StreamingBody implements the read() method
            # so it can be used as a file-like object in this context
            response = vault.restore_snapshot(snapshot)  # type: ignore[arg-type]
        except VaultClientError as e:
            logger.error("Failed to restore snapshot: %s", e)
            return False
        if not 200 <= response.status_code < 300:
            logger.error("Failed to restore snapshot: %s", response.json())
            return False

        return True

    def _get_active_vault_client(self) -> Optional[Vault]:
        """Return an initialized vault client.

        Creates a Vault client and returns it if is active and the charm is authorized.
        Otherwise, returns None.

        Returns:
            Vault: Vault client
        """
        vault = Vault(
            url=self._api_address,
            ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
        )
        if not vault.is_api_available():
            return None
        role_id, secret_id = self._get_approle_auth_secret()
        if not role_id or not secret_id:
            return None
        if not vault.authenticate(AppRole(role_id, secret_id)):
            return None
        if not vault.is_active_or_standby():
            return None
        return vault

    @property
    def _bind_address(self) -> Optional[str]:
        """Fetch the bind address from peer relation and returns it.

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
        """Fetch the ingress address from peer relation and returns it.

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
        """Return the pebble layer to start Vault."""
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

    def _get_peer_node_api_addresses(self) -> List[str]:
        """Return a list of unit addresses that should be a part of the raft cluster."""
        return [
            f"https://{self.app.name}-{i}.{socket.getfqdn().split('.', 1)[-1]}:{self.VAULT_PORT}"
            for i in range(self.app.planned_units())
        ]

    def _get_config_common_name(self) -> str:
        """Return the common name to use for the PKI backend."""
        return cast(str, self.config.get("common_name", ""))

    def _common_name_config_is_valid(self) -> bool:
        """Return whether the config value for the common name is valid."""
        common_name = self._get_config_common_name()
        return common_name != ""

    @property
    def _node_id(self) -> str:
        """Return the node id for vault.

        Example of node id: "vault-k8s-0"
        """
        return f"{self.model.name}-{self.unit.name}"

    @property
    def _certificate_subject(self) -> str:
        return f"{self.app.name}.{self.model.name}.svc.cluster.local"


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
    """Return whether two Vault config file contents match.

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

    new_retry_join_api_addresses = {address["leader_api_addr"] for address in new_retry_joins}
    existing_retry_join_api_addresses = {
        address["leader_api_addr"] for address in existing_retry_joins
    }
    return (
        new_retry_join_api_addresses == existing_retry_join_api_addresses
        and new_content_hcl == existing_config_hcl
    )


def get_common_name_from_certificate(certificate: str) -> str:
    """Get the common name from a certificate."""
    loaded_certificate = x509.load_pem_x509_certificate(certificate.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )


def get_common_name_from_csr(csr: str) -> str:
    """Get the common name from a CSR."""
    loaded_csr = x509.load_pem_x509_csr(csr.encode("utf-8"))
    return str(loaded_csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)  # type: ignore[reportAttributeAccessIssue]


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
