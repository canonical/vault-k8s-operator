#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Dict, List, Tuple, cast

import hcl
from botocore.response import StreamingBody
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequest,
    Mode,
    PrivateKey,
    ProviderCertificate,
    RequirerCSR,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from charms.vault_k8s.v0.vault_autounseal import (
    AutounsealDetails,
    VaultAutounsealProvides,
    VaultAutounsealRequirerRelationBroken,
    VaultAutounsealRequires,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    Vault,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_kv import (
    NewVaultKvClientAttachedEvent,
    VaultKvClientDetachedEvent,
    VaultKvProvides,
)
from charms.vault_k8s.v0.vault_s3 import S3, S3Error
from charms.vault_k8s.v0.vault_tls import File, VaultCertsError, VaultTLSManager
from jinja2 import Environment, FileSystemLoader
from ops import CharmBase, MaintenanceStatus
from ops.charm import (
    ActionEvent,
    CollectStatusEvent,
    InstallEvent,
    RemoveEvent,
)
from ops.framework import EventBase
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

from container import Container

logger = logging.getLogger(__name__)

APPROLE_ROLE_NAME = "charm"
AUTOUNSEAL_MOUNT_PATH = "charm-autounseal"
AUTOUNSEAL_POLICY_PATH = "src/templates/autounseal_policy.hcl"
AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"
AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"
BACKUP_KEY_PREFIX = "vault-backup"
CHARM_POLICY_NAME = "charm-access"
CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
CONFIG_TRANSIT_STANZA_TEMPLATE_NAME = "vault_transit.hcl.j2"
CONTAINER_NAME = "vault"
CONTAINER_TLS_FILE_DIRECTORY_PATH = "/vault/certs"
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"
LOG_FORWARDING_RELATION_NAME = "logging"
PEER_RELATION_NAME = "vault-peers"
PKI_MOUNT = "charm-pki"
PKI_RELATION_NAME = "vault-pki"
PKI_ROLE_NAME = "charm"
PROMETHEUS_ALERT_RULES_PATH = "./src/prometheus_alert_rules"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
S3_RELATION_NAME = "s3-parameters"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_CONFIG_FILE_PATH = "/vault/config/vault.hcl"
VAULT_INITIALIZATION_SECRET_LABEL = "vault-initialization"
VAULT_STORAGE_PATH = "/vault/raft"


@dataclass
class AutounsealConfigurationDetails:
    """Credentials required for configuring auto-unseal on Vault."""

    address: str
    mount_path: str
    key_name: str
    token: str
    ca_cert_path: str


class VaultCharm(CharmBase):
    """Main class to handle Juju events for the vault-k8s charm."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args):
        super().__init__(*args)
        self._service_name = self._container_name = CONTAINER_NAME
        self._container = Container(container=self.unit.get_container(self._container_name))
        self.unit.set_ports(self.VAULT_PORT)
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV4(
            charm=self,
            relationship_name=PKI_RELATION_NAME,
        )
        certificate_request = self._get_certificate_request()
        self.tls_certificates_pki = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
            certificate_requests=[certificate_request] if certificate_request else [],
            mode=Mode.APP,
            refresh_events=[self.on.config_changed],
        )
        self.vault_autounseal_provides = VaultAutounsealProvides(
            self, AUTOUNSEAL_PROVIDES_RELATION_NAME
        )
        self.vault_autounseal_requires = VaultAutounsealRequires(
            self, AUTOUNSEAL_REQUIRES_RELATION_NAME
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
            alert_rules_path=PROMETHEUS_ALERT_RULES_PATH,
        )
        self._logging = LogForwarder(
            charm=self,
            relation_name=LOG_FORWARDING_RELATION_NAME,
        )
        self.tls = VaultTLSManager(
            charm=self,
            workload=self._container,
            service_name=self._container_name,
            tls_directory_path=CONTAINER_TLS_FILE_DIRECTORY_PATH,
            common_name=self._ingress_address if self._ingress_address else "",
            sans_dns=frozenset([socket.getfqdn()]),
            sans_ip=frozenset([self._ingress_address] if self._ingress_address else []),
        )
        self.ingress = IngressPerAppRequirer(
            charm=self,
            port=self.VAULT_PORT,
            strip_prefix=True,
            scheme=lambda: "https",
        )
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)

        configure_events = [
            self.on.update_status,
            self.on.vault_pebble_ready,
            self.on.config_changed,
            self.on[PEER_RELATION_NAME].relation_created,
            self.on[PEER_RELATION_NAME].relation_changed,
            self.on.tls_certificates_pki_relation_joined,
            self.tls_certificates_pki.on.certificate_available,
            self.vault_autounseal_requires.on.vault_autounseal_details_ready,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_created,
            self.vault_autounseal_requires.on.vault_autounseal_provider_relation_broken,
        ]
        for event in configure_events:
            self.framework.observe(event, self._configure)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)
        self.framework.observe(self.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.on.restore_backup_action, self._on_restore_backup_action)
        self.framework.observe(
            self.vault_kv.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )
        self.framework.observe(
            self.vault_kv.on.vault_kv_client_detached, self._on_vault_kv_client_detached
        )
        self.framework.observe(
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken,
            self._on_vault_autounseal_requirer_relation_broken,
        )

    def _on_vault_autounseal_requirer_relation_broken(
        self, event: VaultAutounsealRequirerRelationBroken
    ):
        """Handle the case where the Vault auto-unseal requirer relation is broken.

        Specifically, this means that the Vault auto-unseal provider should
        remove any configuration that was set for the requirer.
        """
        if not self.unit.is_leader():
            return

        vault = self._get_active_vault_client()
        if vault is None:
            logger.warning("Vault is not active, cannot disable vault autounseal")
            return
        vault.destroy_autounseal_credentials(event.relation.id, AUTOUNSEAL_MOUNT_PATH)

    def _generate_and_set_autounseal_credentials(self, relation: Relation) -> None:
        """If leader, generate new credentials for the auto-unseal requirer.

        These credentials are generated and then set in the relation databag so
        that the requiring app can retrieve them, and use them to create tokens
        that have the appropriate permissions to use the autounseal key.
        """
        if not self.unit.is_leader():
            return
        vault = self._get_active_vault_client()
        if vault is None:
            logger.warning("Vault is not active, cannot generate autounseal credentials")
            return

        vault.enable_secrets_engine(SecretsBackend.TRANSIT, AUTOUNSEAL_MOUNT_PATH)

        key_name, approle_id, secret_id = vault.create_autounseal_credentials(
            relation.id,
            AUTOUNSEAL_MOUNT_PATH,
            AUTOUNSEAL_POLICY_PATH,
        )

        self._set_autounseal_relation_data(relation, key_name, approle_id, secret_id)

    def _sync_vault_autounseal(self) -> None:
        """Go through all the vault-autounseal relations and send necessary credentials.

        This looks for any outstanding requests for auto-unseal that may have
        been missed. If there are any, it generates the credentials and sets
        them in the relation databag.
        """
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-autounseal request")
            return
        outstanding_requests = self.vault_autounseal_provides.get_outstanding_requests()
        for relation in outstanding_requests:
            self._generate_and_set_autounseal_credentials(relation)

    def _set_autounseal_relation_data(
        self, relation: Relation, key_name: str, approle_id: str, approle_secret_id: str
    ) -> None:
        """Set the required autounseal data in the relation databag.

        Args:
            relation: Relation for which the auto-unseal data is being set
            key_name: The vault transit key name used for auto-unseal
            approle_id: The AppRole ID which has permission to use this key
            approle_secret_id: The AppRole secret ID
        """
        vault_address = self._get_relation_api_address(relation)
        if not vault_address:
            logger.warning("Vault address not available, ignoring request to set autounseal data")
            return
        ca_cert = (
            self.tls.pull_tls_file_from_workload(File.CA)
            if self.tls.ca_certificate_is_saved()
            else None
        )
        if not ca_cert:
            logger.warning("CA certificate not available, ignoring request to set autounseal data")
            return

        self.vault_autounseal_provides.set_autounseal_data(
            relation,
            vault_address,
            AUTOUNSEAL_MOUNT_PATH,
            key_name,
            approle_id,
            approle_secret_id,
            ca_cert,
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
            if vault.is_seal_type_transit():
                event.add_status(BlockedStatus("Please initialize Vault"))
                return

            event.add_status(
                BlockedStatus("Please initialize Vault or integrate with an auto-unseal provider")
            )
            return
        try:
            if vault.is_sealed():
                if vault.needs_migration():
                    event.add_status(BlockedStatus("Please migrate Vault"))
                    return
                event.add_status(BlockedStatus("Please unseal Vault"))
                return
        except VaultClientError:
            event.add_status(MaintenanceStatus("Seal check failed, waiting for Vault to recover"))
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

    def _configure(self, _: EventBase) -> None:  # noqa: C901
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
        if not self.tls.ca_certificate_secret_exists():
            return
        if not self.tls.tls_file_pushed_to_workload(File.CA):
            return
        if not self.tls.tls_file_pushed_to_workload(File.CERT):
            return
        if not self.tls.tls_file_pushed_to_workload(File.KEY):
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
        try:
            if vault.is_sealed():
                return
        except VaultClientError:
            return
        if not (vault := self._get_active_vault_client()):
            return
        self._configure_pki_secrets_engine()
        self._sync_vault_autounseal()
        self._sync_vault_kv()
        self._sync_vault_pki()

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
        try:
            if vault.is_sealed():
                return
        except VaultClientError:
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
            egress_subnets=event.egress_subnets,
            nonce=event.nonce,
        )

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        label = self._get_vault_kv_secret_label(unit_name=event.unit_name)
        self._remove_juju_secret_by_label(label=label)

    def _configure_pki_secrets_engine(self) -> None:  # noqa: C901
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
        config_common_name = self._get_config_common_name()
        if not config_common_name:
            logger.error("Common name is not set in the charm config")
            return
        provider_certificate, private_key = self._get_pki_intermediate_ca()
        if not provider_certificate:
            return
        vault.enable_secrets_engine(SecretsBackend.PKI, PKI_MOUNT)
        existing_ca_certificate = vault.get_intermediate_ca(mount=PKI_MOUNT)
        existing_cert = (
            Certificate.from_string(existing_ca_certificate) if existing_ca_certificate else None
        )
        if existing_cert and existing_cert == provider_certificate.certificate:
            if not self._intermediate_ca_exceeds_role_ttl(vault, existing_cert):
                self.tls_certificates_pki.renew_certificate(
                    provider_certificate,
                )
                logger.debug("Renewing CA certificate")
                return
            logger.debug("CA certificate already set in the PKI secrets engine")
            return
        self.vault_pki.revoke_all_certificates()
        vault.import_ca_certificate_and_key(
            certificate=str(provider_certificate.certificate),
            private_key=str(private_key),
            mount=PKI_MOUNT,
        )
        issued_certificates_validity = self._calculate_pki_certificates_ttl(
            provider_certificate.certificate
        )
        if not vault.is_common_name_allowed_in_pki_role(
            role=PKI_ROLE_NAME,
            mount=PKI_MOUNT,
            common_name=config_common_name,
        ) or issued_certificates_validity != vault.get_role_max_ttl(
            role=PKI_ROLE_NAME, mount=PKI_MOUNT
        ):
            vault.create_or_update_pki_charm_role(
                allowed_domains=config_common_name,
                mount=PKI_MOUNT,
                role=PKI_ROLE_NAME,
                max_ttl=f"{issued_certificates_validity}s",
            )
        # Can run only after the first issuer has been actually created.
        try:
            vault.make_latest_pki_issuer_default(mount=PKI_MOUNT)
        except VaultClientError as e:
            logger.error("Failed to make latest issuer default: %s", e)

    def _intermediate_ca_exceeds_role_ttl(
        self, vault: Vault, intermediate_ca_certificate: Certificate
    ) -> bool:
        """Check if the intermediate CA's remaining validity exceeds the role's max TTL.

        Vault PKI enforces that issued certificates cannot outlast their signing CA.
        This method ensures that the intermediate CA's remaining validity period
        is longer than the maximum TTL allowed for certificates issued by this role.
        """
        current_ttl = vault.get_role_max_ttl(role=PKI_ROLE_NAME, mount=PKI_MOUNT)
        if (
            not current_ttl
            or not intermediate_ca_certificate.expiry_time
            or not intermediate_ca_certificate.validity_start_time
        ):
            return False
        certificate_validity = (
            intermediate_ca_certificate.expiry_time
            - intermediate_ca_certificate.validity_start_time
        )
        certificate_validity_seconds = certificate_validity.total_seconds()
        return certificate_validity_seconds > current_ttl

    def _calculate_pki_certificates_ttl(self, certificate: Certificate) -> int:
        """Calculate the maximum allowed validity of certificates issued by PKI.

        Return half the CA certificate validity in seconds.
        """
        if not certificate.expiry_time or not certificate.validity_start_time:
            raise ValueError("Invalid CA certificate with no expiry time or validity start time")
        ca_validity_time = certificate.expiry_time - certificate.validity_start_time
        ca_validity_seconds = ca_validity_time.total_seconds()
        return int(ca_validity_seconds / 2)

    def _get_pki_intermediate_ca(
        self,
    ) -> Tuple[ProviderCertificate | None, PrivateKey | None]:
        """Get the intermediate CA certificate."""
        certificate_request = self._get_certificate_request()
        if not certificate_request:
            logger.error("Certificate request is not valid")
            return None, None
        provider_certificate, private_key = self.tls_certificates_pki.get_assigned_certificate(
            certificate_request=certificate_request
        )
        if not provider_certificate:
            logger.debug("No intermediate CA certificate available")
            return None, None
        if not private_key:
            logger.debug("No private key available")
            return None, None
        return provider_certificate, private_key

    def _get_certificate_request(self) -> CertificateRequest | None:
        common_name = self._get_config_common_name()
        if not common_name:
            return None
        return CertificateRequest(
            common_name=common_name,
            is_ca=True,
        )

    def _sync_vault_pki(self) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        outstanding_pki_requests = self.vault_pki.get_outstanding_certificate_requests()
        for pki_request in outstanding_pki_requests:
            self._generate_pki_certificate_for_requirer(
                requirer_csr=pki_request,
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
                egress_subnets=kv_request.egress_subnets,
                nonce=kv_request.nonce,
            )

    def _generate_kv_for_requirer(
        self,
        relation: Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnets: List[str],
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
        vault.enable_secrets_engine(SecretsBackend.KV_V2, mount)
        self._ensure_unit_credentials(vault, relation, unit_name, mount, nonce, egress_subnets)
        self._set_kv_relation_data(relation, mount, ca_certificate, egress_subnets)
        self._remove_stale_nonce(relation=relation, nonce=nonce)

    def _generate_pki_certificate_for_requirer(self, requirer_csr: RequirerCSR):
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
        if not vault.is_pki_role_created(role=PKI_ROLE_NAME, mount=PKI_MOUNT):
            logger.debug("PKI role not created")
            return
        provider_certificate, _ = self._get_pki_intermediate_ca()
        if not provider_certificate:
            return
        allowed_cert_validity = self._calculate_pki_certificates_ttl(
            provider_certificate.certificate
        )
        certificate = vault.sign_pki_certificate_signing_request(
            mount=PKI_MOUNT,
            role=PKI_ROLE_NAME,
            csr=str(requirer_csr.certificate_signing_request),
            common_name=requirer_csr.certificate_signing_request.common_name,
            ttl=f"{allowed_cert_validity}s",
        )
        if not certificate:
            logger.debug("Failed to sign the certificate")
            return
        provider_certificate = ProviderCertificate(
            relation_id=requirer_csr.relation_id,
            certificate=Certificate.from_string(certificate.certificate),
            certificate_signing_request=requirer_csr.certificate_signing_request,
            ca=Certificate.from_string(certificate.ca),
            chain=[Certificate.from_string(cert) for cert in certificate.chain],
        )
        self.vault_pki.set_relation_certificate(
            provider_certificate=provider_certificate,
        )

    def _on_authorize_charm_action(self, event: ActionEvent) -> None:
        if not self.unit.is_leader():
            event.fail("This action must be run on the leader unit.")
            return

        secret_id = event.params.get("secret-id", "")
        try:
            token_secret = self.model.get_secret(id=secret_id)
            token = token_secret.get_content(refresh=True).get("token", "")
        except SecretNotFoundError:
            event.fail(
                "The secret id provided could not be found by the charm. Please grant the token secret to the charm."
            )
            return
        vault = Vault(self._api_address, self.tls.get_tls_file_path_in_charm(File.CA))
        if not vault.authenticate(Token(token)):
            event.fail(
                "The token provided is not valid. Please use a Vault token with the appropriate permissions."
            )
            return

        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.update_autopilot_config()
            vault.enable_approle_auth_method()
            vault.configure_policy(policy_name=CHARM_POLICY_NAME, policy_path=CHARM_POLICY_PATH)
            cidrs = [f"{self._bind_address}/24"]
            role_id = vault.configure_approle(
                role_name=APPROLE_ROLE_NAME,
                cidrs=cidrs,
                policies=[CHARM_POLICY_NAME, "default"],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            secret_id = vault.generate_role_secret_id(name=APPROLE_ROLE_NAME, cidrs=cidrs)
            self._set_juju_secret(
                VAULT_CHARM_APPROLE_SECRET_LABEL,
                {"role-id": role_id, "secret-id": secret_id},
                description="The authentication details for the charm's access to vault.",
            )
            event.set_results(
                {"result": "Charm authorized successfully. You may now remove the secret."}
            )
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")

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
            content=response.raw,  # type: ignore[reportArgumentType]
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
                    self._remove_juju_secret_by_label(VAULT_CHARM_APPROLE_SECRET_LABEL)
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

    def _check_s3_pre_requisites(self) -> str | None:
        """Check if the S3 pre-requisites are met."""
        if not self.unit.is_leader():
            return "Only leader unit can perform backup operations"
        if not self._is_relation_created(S3_RELATION_NAME):
            return "S3 relation not created"
        if missing_parameters := self._get_missing_s3_parameters():
            return "S3 parameters missing ({})".format(", ".join(missing_parameters))
        return None

    def _get_backup_key(self) -> str:
        """Return the backup key.

        Returns:
            str: The backup key
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return f"{BACKUP_KEY_PREFIX}-{self.model.name}-{timestamp}"

    def _set_kv_relation_data(
        self,
        relation: Relation,
        mount: str,
        ca_certificate: str,
        egress_subnets: List[str],
    ) -> None:
        """Set relation data for vault-kv.

        Args:
            relation: Relation
            mount: mount name
            ca_certificate: CA certificate
            egress_subnets: egress subnet
        """
        self.vault_kv.set_mount(relation, mount)
        vault_url = self._get_relation_api_address(relation)
        self.vault_kv.set_ca_certificate(relation, ca_certificate)
        self.vault_kv.set_egress_subnets(relation, egress_subnets)
        if vault_url is not None:
            self.vault_kv.set_vault_url(relation, vault_url)

    def _ensure_unit_credentials(
        self,
        vault: Vault,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnets: List[str],
    ):
        """Ensure a unit has credentials to access the vault-kv mount."""
        policy_name = role_name = mount + "-" + unit_name.replace("/", "-")
        vault.configure_policy(policy_name, "src/templates/kv_mount.hcl", mount=mount)
        role_id = vault.configure_approle(
            role_name,
            policies=[policy_name],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        juju_secret_label = self._get_vault_kv_secret_label(unit_name=unit_name)
        secret = self._create_or_update_kv_secret(
            vault,
            nonce,
            relation,
            role_id,
            role_name,
            egress_subnets,
            juju_secret_label,
        )
        self.vault_kv.set_unit_credentials(relation, nonce, secret)

    def _create_or_update_kv_secret(
        self,
        vault: Vault,
        nonce: str,
        relation: Relation,
        role_id: str,
        role_name: str,
        egress_subnets: List[str],
        label: str,
    ) -> Secret:
        """Create or update a KV secret for a unit.

        Fetch secret id from peer relation, if it exists, update the secret,
        otherwise create it.
        """
        # TODO bug: https://bugs.launchpad.net/juju/+bug/2075153
        # Until the referenced bug is fixed we must pass the secret ID here
        # not to lose the secret://modeluuid:secretID format
        current_credentials = self.vault_kv.get_credentials(relation)
        secret_id = current_credentials.get(nonce, None)
        if secret_id is None:
            return self._create_kv_secret(
                vault, relation, role_id, role_name, egress_subnets, label
            )
        else:
            return self._update_kv_secret(
                vault, relation, role_name, egress_subnets, label, secret_id
            )

    def _create_kv_secret(
        self,
        vault: Vault,
        relation: Relation,
        role_id: str,
        role_name: str,
        egress_subnets: List[str],
        label: str,
    ) -> Secret:
        """Create a vault kv secret, store its id in the peer relation and return it."""
        role_secret_id = vault.generate_role_secret_id(role_name, egress_subnets)
        secret = self.app.add_secret(
            {"role-id": role_id, "role-secret-id": role_secret_id},
            label=label,
        )
        if secret.id is None:
            raise RuntimeError(f"Unexpected error, just created secret {label!r} has no id")
        secret.grant(relation)
        return secret

    def _update_kv_secret(
        self,
        vault: Vault,
        relation: Relation,
        role_name: str,
        egress_subnets: List[str],
        label: str,
        secret_id: str,
    ) -> Secret:
        """Update a vault kv secret if the unit subnet is not in the cidr list."""
        secret = self.model.get_secret(id=secret_id, label=label)
        secret.grant(relation)
        credentials = secret.get_content(refresh=True)
        role_secret_id_data = vault.read_role_secret(role_name, credentials["role-secret-id"])
        # if unit subnet is already in cidr_list, skip
        if sorted(egress_subnets) == sorted(role_secret_id_data["cidr_list"]):
            return secret
        credentials["role-secret-id"] = vault.generate_role_secret_id(role_name, egress_subnets)
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

    def _get_relation_api_address(self, relation: Relation) -> str | None:
        """Fetch the api address from relation and returns it.

        Example: "https://10.152.183.20:8200"
        """
        binding = self.model.get_binding(relation)
        if binding is None:
            return None
        return f"https://{binding.network.ingress_address}:{self.VAULT_PORT}"

    def _common_name_config_is_valid(self) -> bool:
        """Return whether the config value for the common name is valid."""
        common_name = self._get_config_common_name()
        return common_name != ""

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

    def _get_autounseal_configuration(self) -> AutounsealConfigurationDetails | None:
        """Retrieve the autounseal configuration details, if available.

        Returns the autounseal configuration details if all the required
        information is available, otherwise `None`.
        """
        autounseal_details = self.vault_autounseal_requires.get_details()
        if not autounseal_details:
            return None

        self.tls.push_autounseal_ca_cert(autounseal_details.ca_certificate)

        return AutounsealConfigurationDetails(
            autounseal_details.address,
            autounseal_details.mount_path,
            autounseal_details.key_name,
            self._get_autounseal_vault_token(autounseal_details),
            self.tls.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA),
        )

    def _get_autounseal_vault_token(self, autounseal_details: AutounsealDetails) -> str:
        """Retrieve the auto-unseal Vault token, or generate a new one if required.

        Retrieves the last used token from Juju secrets, and validates that it
        is still valid. If the token is not valid, a new token is generated and
        stored in the Juju secret. A valid token is returned.

        Args:
            autounseal_details: The autounseal configuration details.

        Returns:
            A periodic Vault token that can be used for auto-unseal.

        """
        vault = Vault(
            url=autounseal_details.address,
            ca_cert_path=self.tls.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA),
        )
        existing_token = self._get_juju_secret_field(AUTOUNSEAL_TOKEN_SECRET_LABEL, "token")
        # If we don't already have a token, or if the existing token is invalid,
        # authenticate with the AppRole details to generate a new token.
        if not existing_token or not vault.authenticate(Token(existing_token)):
            vault.authenticate(AppRole(autounseal_details.role_id, autounseal_details.secret_id))
            self._set_juju_secret(AUTOUNSEAL_TOKEN_SECRET_LABEL, {"token": vault.token})
        return vault.token

    def _get_juju_secret_content(self, label: str) -> Dict[str, str] | None:
        """Retrieve the latest revision of the secret content from Juju.

        Args:
            label: The label of the secret.

        Returns:
            The secret is returned, or `None` if the secret does not exist or
              there is an error retrieving the secret.
        """
        try:
            secret = self.model.get_secret(label=label)
            return secret.get_content(refresh=True)
        except SecretNotFoundError:
            return None
        except ModelError as e:
            logger.warning("Failed to retrieve secret `%s`: %s", label, e)
            return None

    def _get_juju_secret_field(self, label: str, field: str) -> str | None:
        """Retrieve the latest revision of the secret content from Juju.

        Args:
            label: The label of the secret.
            field: The field to retrieve from the secret.

        Returns:
            The value of the field is returned, or `None` if the field does not
            exist.

            If the secret does not exist, or there is an error retrieving the secret, `None` is returned.
        """
        content = self._get_juju_secret_content(label)
        return content.get(field) if content else None

    def _get_juju_secret_fields(self, label: str, *fields: str) -> Tuple[str | None, ...]:
        """Retrieve the latest revision of the secret content from Juju.

        Args:
            label: The label of the secret.
            fields: The fields to retrieve from the secret.

        Returns:
            The value of the fields are returned as a tuple, or `None` if the field does not
            exist.

            If the secret does not exist, or there is an error retrieving the secret, `None` is returned for all fields.
        """
        content = self._get_juju_secret_content(label)
        return (
            tuple(content.get(field) for field in fields)
            if content
            else tuple(None for _ in fields)
        )

    def _set_juju_secret(
        self, label: str, content: Dict[str, str], description: str | None = None
    ) -> None:
        """Set the secret content at `label`, overwrite if it already exists.

        Args:
            label: The label of the secret.
            content: The content of the secret.
            description: The description of the secret.
        """
        try:
            secret = self.model.get_secret(label=label)
        except SecretNotFoundError:
            self.app.add_secret(content, label=label, description=description)
            return
        except ModelError as e:
            logger.warning("Failed to retrieve secret `%s`: %s", label, e)
            return
        secret.set_content(content)

    def _generate_vault_config_file(self) -> None:
        """Handle the creation of the Vault config file."""
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",
            }
            for node_api_address in self._get_peer_node_api_addresses()
        ]

        content = _render_vault_config_file(
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
            autounseal_details=self._get_autounseal_configuration(),
        )
        existing_content = ""
        if self._container.exists(path=VAULT_CONFIG_FILE_PATH):
            existing_content_stringio = self._container.pull(path=VAULT_CONFIG_FILE_PATH)
            existing_content = existing_content_stringio.read()

        if not config_file_content_matches(existing_content=existing_content, new_content=content):
            self._push_config_file_to_workload(content=content)
            # If the seal type has changed, we need to restart Vault to apply
            # the changes. SIGHUP is currently only supported as a beta feature
            # for the enterprise version in Vault 1.16+
            if _seal_type_has_changed(existing_content, content):
                if self._vault_service_is_running():
                    self._container.restart(self._service_name)

    def _push_config_file_to_workload(self, content: str):
        """Push the config file to the workload."""
        self._container.push(path=VAULT_CONFIG_FILE_PATH, source=content)
        logger.info("Pushed %s config file", VAULT_CONFIG_FILE_PATH)

    def _get_approle_auth_secret(self) -> Tuple[str | None, str | None]:
        """Get the vault approle login details secret.

        Returns:
            The root token and unseal keys.
        """
        role_id, secret_id = self._get_juju_secret_fields(
            VAULT_CHARM_APPROLE_SECRET_LABEL, "role-id", "secret-id"
        )
        return role_id, secret_id

    def _remove_juju_secret_by_label(self, label: str):
        """Remove the specified secret if it exists."""
        try:
            juju_secret = self.model.get_secret(label=label)
            juju_secret.remove_all_revisions()
        except SecretNotFoundError:
            return

    def _get_vault_kv_secret_label(self, unit_name: str):
        unit_name_dash = unit_name.replace("/", "-")
        return f"{KV_SECRET_PREFIX}{unit_name_dash}"

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
        role_id, secret_id = self._get_approle_auth_secret()
        return bool(role_id and secret_id)

    def _create_raft_snapshot(self) -> IO[bytes] | None:
        """Create a snapshot of Vault.

        Returns:
            The snapshot content as a file like object, or None if the snapshot
            could not be created.
        """
        if not (vault := self._get_active_vault_client()):
            logger.error("Failed to get Vault client, cannot create snapshot.")
            return None
        response = vault.create_snapshot()
        return response.raw  # type: ignore[reportReturnType]

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
            response = vault.restore_snapshot(snapshot)
        except VaultClientError as e:
            logger.error("Failed to restore snapshot: %s", e)
            return False
        if not 200 <= response.status_code < 300:
            logger.error("Failed to restore snapshot: %s", response.json())
            return False

        return True

    def _get_active_vault_client(self) -> Vault | None:
        """Return an initialized vault client.

        Returns:
            Vault: An active Vault client configured with the cluster address
                   and CA certificate, and authorized with the AppRole
                   credentials set upon initial authorization of the charm, or
                   `None` if the client could not be successfully created or
                   has not been authorized.
        """
        try:
            vault = Vault(
                url=self._api_address,
                ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
            )
        except VaultCertsError as e:
            logger.warning("Failed to get Vault client: %s", e)
            return None
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
    def _bind_address(self) -> str | None:
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
    def _ingress_address(self) -> str | None:
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

    @property
    def _node_id(self) -> str:
        """Return the node id for vault.

        Example of node id: "vault-k8s-0"
        """
        return f"{self.model.name}-{self.unit.name}"

    @property
    def _certificate_subject(self) -> str:
        return f"{self.app.name}.{self.model.name}.svc.cluster.local"


def _render_vault_config_file(
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
    autounseal_details: AutounsealConfigurationDetails | None = None,
) -> str:
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
        autounseal_address=autounseal_details.address if autounseal_details else None,
        autounseal_key_name=autounseal_details.key_name if autounseal_details else None,
        autounseal_mount_path=autounseal_details.mount_path if autounseal_details else None,
        autounseal_token=autounseal_details.token if autounseal_details else None,
        autounseal_tls_ca_cert=autounseal_details.ca_cert_path if autounseal_details else None,
    )
    return content


def _seal_type_has_changed(content_a: str, content_b: str) -> bool:
    """Check if the seal type has changed between two versions of the Vault configuration file.

    Currently only checks if the transit stanza is present or not, since this
    is all we support. This function will need to be extended to support
    alternate cases if and when we support them.
    """
    config_a = hcl.loads(content_a)
    config_b = hcl.loads(content_b)
    return _contains_transit_stanza(config_a) != _contains_transit_stanza(config_b)


def _contains_transit_stanza(config: dict) -> bool:
    return "seal" in config and "transit" in config["seal"]


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


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
