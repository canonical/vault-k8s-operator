#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
import socket
from datetime import datetime
from typing import Any, Dict, List, Tuple

from botocore.response import StreamingBody
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    Mode,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from charms.vault_k8s.v0.juju_facade import (
    JujuFacade,
    NoSuchSecretError,
    SecretRemovedError,
)
from charms.vault_k8s.v0.vault_autounseal import (
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from charms.vault_k8s.v0.vault_client import (
    AuditDeviceType,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_helpers import (
    PEER_RELATION_NAME,
    VAULT_PORT,
    VaultHelpers,
    config_file_content_matches,
    render_vault_config_file,
    seal_type_has_changed,
)
from charms.vault_k8s.v0.vault_kv import (
    NewVaultKvClientAttachedEvent,
    VaultKvClientDetachedEvent,
    VaultKvProvides,
)
from charms.vault_k8s.v0.vault_managers import (
    AutounsealConfigurationDetails,
    File,
    VaultAutounsealProviderManager,
    VaultAutounsealRequirerManager,
    VaultCertsError,
    VaultTLSManager,
)
from charms.vault_k8s.v0.vault_s3 import S3, S3Error
from ops import CharmBase, MaintenanceStatus, main
from ops.charm import (
    ActionEvent,
    CollectStatusEvent,
    InstallEvent,
    RemoveEvent,
)
from ops.framework import EventBase
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    ModelError,
    Relation,
    WaitingStatus,
)
from ops.pebble import ChangeError, Layer, PathError

from container import Container

logger = logging.getLogger(__name__)

APPROLE_ROLE_NAME = "charm"
AUTOUNSEAL_MOUNT_PATH = "charm-autounseal"
AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"
BACKUP_KEY_PREFIX = "vault-backup"
CHARM_POLICY_NAME = "charm-access"
CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
CONFIG_TRANSIT_STANZA_TEMPLATE_NAME = "vault_transit.hcl.j2"
CONTAINER_NAME = "vault"
CONTAINER_TLS_FILE_DIRECTORY_PATH = "/vault/certs"
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"
LOG_FORWARDING_RELATION_NAME = "logging"
PKI_MOUNT = "charm-pki"
PKI_RELATION_NAME = "vault-pki"
PKI_ROLE_NAME = "charm"
PROMETHEUS_ALERT_RULES_PATH = "./src/prometheus_alert_rules"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
S3_RELATION_NAME = "s3-parameters"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CONFIG_FILE_PATH = "/vault/config/vault.hcl"
VAULT_STORAGE_PATH = "/vault/raft"


@trace_charm(
    tracing_endpoint="_tracing_endpoint",
    server_cert="_tracing_server_cert",
    extra_types=(TLSCertificatesProvidesV4,),
)
class VaultCharm(CharmBase):
    """Main class to handle Juju events for the vault-k8s charm."""

    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args: Any):
        super().__init__(*args)
        self.juju_facade = JujuFacade(self)
        self.vault_helpers = VaultHelpers(self)
        self._service_name = self._container_name = CONTAINER_NAME
        self._container = Container(container=self.unit.get_container(self._container_name))
        self.unit.set_ports(VAULT_PORT)
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV4(
            charm=self,
            relationship_name=PKI_RELATION_NAME,
        )
        certificate_request = self.vault_helpers.get_certificate_request()
        self.tls_certificates_pki = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
            certificate_requests=[certificate_request] if certificate_request else [],
            mode=Mode.APP,
            refresh_events=[self.on.config_changed],
        )
        self.tracing = TracingEndpointRequirer(self, protocols=["otlp_http"])
        self._tracing_endpoint, self._tracing_server_cert = charm_tracing_config(
            self.tracing, cert_path=None
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
                    "static_configs": [{"targets": [f"*:{VAULT_PORT}"]}],
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
            common_name=self.vault_helpers.ingress_address
            if self.vault_helpers.ingress_address
            else "",
            sans_dns=frozenset([socket.getfqdn()]),
            sans_ip=frozenset(
                [self.vault_helpers.ingress_address] if self.vault_helpers.ingress_address else []
            ),
        )
        self.ingress = IngressPerAppRequirer(
            charm=self,
            port=VAULT_PORT,
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
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken,
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

    def _on_install(self, event: InstallEvent):
        """Handle the install charm event."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_vault_data()

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa: C901
        """Handle the collect status event."""
        if (
            self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME)
            and not self.vault_helpers.common_name_config_is_valid()
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
        if not self.vault_helpers.peer_relation_exists():
            event.add_status(WaitingStatus("Waiting for peer relation"))
            return
        if not self.vault_helpers.bind_address or not self.vault_helpers.ingress_address:
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
        vault = VaultClient(
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
        if not self.vault_helpers.get_approle_auth_secret():
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
        if not self.vault_helpers.peer_relation_exists():
            return
        if not self.vault_helpers.bind_address or not self.vault_helpers.ingress_address:
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
        try:
            vault = VaultClient(
                url=self._api_address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA)
            )
        except VaultCertsError as e:
            logger.error("Failed to get TLS file path: %s", e)
            return
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
        self._sync_vault_autounseal(vault)
        self._sync_vault_kv(vault)
        self._sync_vault_pki(vault)

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
        if not (approle := self.vault_helpers.get_approle_auth_secret()):
            return
        vault = VaultClient(url=self._api_address, ca_cert_path=None)
        if not vault.is_api_available():
            return
        if not vault.is_initialized():
            return
        try:
            if vault.is_sealed():
                return
        except VaultClientError:
            return
        vault.authenticate(approle)
        if (
            vault.is_node_in_raft_peers(self.vault_helpers.node_id)
            and vault.get_num_raft_peers() > 1
        ):
            vault.remove_raft_node(self.vault_helpers.node_id)

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
        """Handle vault-kv-client attached event."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        self._generate_kv_for_requirer(
            vault=vault,
            relation=event.relation,
            app_name=event.app_name,
            unit_name=event.unit_name,
            mount_suffix=event.mount_suffix,
            egress_subnets=event.egress_subnets,
            nonce=event.nonce,
        )

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        label = self._get_vault_kv_secret_label(unit_name=event.unit_name)
        self.juju_facade.remove_secret(label=label)

    def _configure_pki_secrets_engine(self) -> None:  # noqa: C901
        """Configure the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        if not self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("TLS Certificates PKI relation not created, skipping")
            return
        if not self.vault_helpers.common_name_config_is_valid():
            logger.debug("Common name config is not valid, skipping")
            return
        config_common_name = self.juju_facade.get_string_config("common_name")
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
        self, vault: VaultClient, intermediate_ca_certificate: Certificate
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
        certificate_request = self.vault_helpers.get_certificate_request()
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

    def _sync_vault_autounseal(self, vault_client: VaultClient) -> None:
        """Sync the vault autounseal relation."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-autounseal request")
            return
        autounseal_provider_manager = VaultAutounsealProviderManager(
            charm=self,
            client=vault_client,
            provides=self.vault_autounseal_provides,
            ca_cert=self.tls.pull_tls_file_from_workload(File.CA),
            mount_path=AUTOUNSEAL_MOUNT_PATH,
        )
        relations_without_credentials = (
            self.vault_autounseal_provides.get_relations_without_credentials()
        )
        if relations_without_credentials:
            vault_client.enable_secrets_engine(
                SecretsBackend.TRANSIT, autounseal_provider_manager.mount_path
            )
        for relation in relations_without_credentials:
            relation_address = self.vault_helpers.get_relation_api_address(relation)
            if not relation_address:
                logger.warning("Relation address not found for relation %s", relation.id)
                continue
            autounseal_provider_manager.create_credentials(relation, relation_address)
        autounseal_provider_manager.clean_up_credentials()

    def _sync_vault_pki(self, vault: VaultClient) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        outstanding_pki_requests = self.vault_pki.get_outstanding_certificate_requests()
        for pki_request in outstanding_pki_requests:
            self._generate_pki_certificate_for_requirer(
                vault=vault,
                requirer_csr=pki_request,
            )

    def _sync_vault_kv(self, vault: VaultClient) -> None:
        """Goes through all the vault-kv relations and sends necessary KV information."""
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        kv_requests = self.vault_kv.get_kv_requests()
        for kv_request in kv_requests:
            self._generate_kv_for_requirer(
                relation=kv_request.relation,
                vault=vault,
                app_name=kv_request.app_name,
                unit_name=kv_request.unit_name,
                mount_suffix=kv_request.mount_suffix,
                egress_subnets=kv_request.egress_subnets,
                nonce=kv_request.nonce,
            )

    def _generate_kv_for_requirer(
        self,
        vault: VaultClient,
        relation: Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnets: List[str],
        nonce: str,
    ):
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        ca_certificate = self.tls.pull_tls_file_from_workload(File.CA)
        if not ca_certificate:
            logger.debug("Vault CA certificate not available")
            return
        if not (vault_url := self.vault_helpers.get_relation_api_address(relation)):
            logger.debug("Failed to get Vault URL for relation %s", relation.id)
            return
        mount = f"charm-{app_name}-{mount_suffix}"
        vault.enable_secrets_engine(SecretsBackend.KV_V2, mount)
        secret_id = self._ensure_unit_credentials(
            vault=vault,
            relation=relation,
            unit_name=unit_name,
            mount=mount,
            nonce=nonce,
            egress_subnets=egress_subnets,
        )
        self.vault_kv.set_kv_data(
            relation=relation,
            mount=mount,
            ca_certificate=ca_certificate,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id=secret_id,
        )
        self._remove_stale_nonce(relation=relation, nonce=nonce)

    def _generate_pki_certificate_for_requirer(
        self, vault: VaultClient, requirer_csr: RequirerCertificateRequest
    ):
        """Generate a PKI certificate for a TLS requirer."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        if not self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("TLS Certificates PKI relation not created")
            return
        common_name = self.juju_facade.get_string_config("common_name")
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
            if not (
                token := self.juju_facade.get_latest_secret_content(id=secret_id).get("token", "")
            ):
                event.fail("Token not found in the secret. Please provide a valid token secret.")
                return
        except (NoSuchSecretError, SecretRemovedError):
            event.fail(
                "The secret id provided could not be found by the charm. Please grant the token secret to the charm."
            )
            return
        vault = VaultClient(self._api_address, self.tls.get_tls_file_path_in_charm(File.CA))
        if not vault.authenticate(Token(token)):
            event.fail(
                "The token provided is not valid. Please use a Vault token with the appropriate permissions."
            )
            return

        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.create_or_update_policy_from_file(name=CHARM_POLICY_NAME, path=CHARM_POLICY_PATH)
            cidrs = [f"{self.vault_helpers.bind_address}/24"]
            role_id = vault.create_or_update_approle(
                name=APPROLE_ROLE_NAME,
                cidrs=cidrs,
                policies=[CHARM_POLICY_NAME, "default"],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            secret_id = vault.generate_role_secret_id(name=APPROLE_ROLE_NAME, cidrs=cidrs)
            self.vault_helpers.set_approle_auth_secret(role_id, secret_id)
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
            if approle := self.vault_helpers.get_approle_auth_secret():
                vault = VaultClient(
                    url=self._api_address,
                    ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
                )
                if approle and not vault.authenticate(approle):
                    self.vault_helpers.remove_approle_auth_secret()
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
        if not self.juju_facade.relation_exists(S3_RELATION_NAME):
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

    def _is_vault_kv_role_configured(
        self,
        vault: VaultClient,
        label: str,
        egress_subnets: List[str],
        role_name: str,
        credentials_juju_secret_id: str,
    ) -> bool:
        try:
            role_secret_id = self.juju_facade.get_latest_secret_content(
                label=label,
                id=credentials_juju_secret_id,
            ).get("role-secret-id")
        except NoSuchSecretError:
            return False
        if not role_secret_id:
            return False
        role_data = vault.read_role_secret(role_name, role_secret_id)
        if egress_subnets in role_data["cidr_list"]:
            return True
        return False

    def _ensure_unit_credentials(
        self,
        vault: VaultClient,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnets: List[str],
    ) -> str:
        """Ensure a unit has credentials to access the vault-kv mount."""
        policy_name = role_name = mount + "-" + unit_name.replace("/", "-")

        juju_secret_label = self._get_vault_kv_secret_label(unit_name=unit_name)
        current_credentials = self.vault_kv.get_credentials(relation)
        credentials_juju_secret_id = current_credentials.get(nonce, None)

        if self._is_vault_kv_role_configured(
            vault=vault,
            label=juju_secret_label,
            egress_subnets=egress_subnets,
            role_name=role_name,
            credentials_juju_secret_id=credentials_juju_secret_id,
        ):
            logger.info("Vault KV role already configured for the provided egress subnets")
            return credentials_juju_secret_id
        vault.create_or_update_policy_from_file(
            policy_name, "src/templates/kv_mount.hcl", mount=mount
        )
        role_id = vault.create_or_update_approle(
            role_name,
            policies=[policy_name],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        role_secret_id = vault.generate_role_secret_id(role_name, egress_subnets)
        secret = self.juju_facade.set_app_secret_content(
            content={"role-id": role_id, "role-secret-id": role_secret_id},
            label=juju_secret_label,
        )
        self.juju_facade.grant_secret(relation, secret=secret)
        if not secret.id:
            raise ValueError(
                f"Unexpected error, just created secret {juju_secret_label!r} has no id"
            )
        return secret.id

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

    def _vault_service_is_running(self) -> bool:
        """Check if the vault service is running."""
        try:
            return self._container.get_service(service_name=self._service_name).is_running()
        except ModelError:
            return False

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

    def _generate_vault_config_file(self) -> None:
        """Handle the creation of the Vault config file."""
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",
            }
            for node_api_address in self._get_peer_node_api_addresses()
        ]

        autounseal_configuration_details = self._get_vault_autounseal_configuration()

        content = render_vault_config_file(
            default_lease_ttl=self.juju_facade.get_string_config("default_lease_ttl"),
            max_lease_ttl=self.juju_facade.get_string_config("max_lease_ttl"),
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tcp_address=f"[::]:{VAULT_PORT}",
            tls_cert_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self.vault_helpers.node_id,
            retry_joins=retry_joins,
            autounseal_details=autounseal_configuration_details,
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
            if seal_type_has_changed(existing_content, content):
                if self._vault_service_is_running():
                    self._container.restart(self._service_name)

    def _get_vault_autounseal_configuration(self) -> AutounsealConfigurationDetails | None:
        autounseal_relation_details = self.vault_autounseal_requires.get_details()
        if not autounseal_relation_details:
            return None
        autounseal_requirer_manager = VaultAutounsealRequirerManager(
            self, self.vault_autounseal_requires
        )
        self.tls.push_autounseal_ca_cert(autounseal_relation_details.ca_certificate)
        provider_vault_token = autounseal_requirer_manager.get_provider_vault_token(
            autounseal_relation_details, self.tls.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA)
        )
        return AutounsealConfigurationDetails(
            autounseal_relation_details.address,
            autounseal_relation_details.mount_path,
            autounseal_relation_details.key_name,
            provider_vault_token,
            self.tls.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA),
        )

    def _push_config_file_to_workload(self, content: str):
        """Push the config file to the workload."""
        self._container.push(path=VAULT_CONFIG_FILE_PATH, source=content)
        logger.info("Pushed %s config file", VAULT_CONFIG_FILE_PATH)

    def _get_missing_s3_parameters(self) -> List[str]:
        """Return the list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        return [param for param in REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _set_pebble_plan(self) -> None:
        """Set the pebble plan if different from the currently applied one."""
        plan = self._container.get_plan()
        layer = self._vault_layer
        if plan.services != layer.services:
            self._container.add_layer(self._container_name, layer, combine=True)
            self._container.replan()
            logger.info("Pebble layer added")

    def _restore_vault(self, snapshot: StreamingBody) -> bool:
        """Restore vault using a raft snapshot.

        Args:
            snapshot: Snapshot to be restored as a StreamingBody from the S3 storage.

        Returns:
            bool: True if the restore was successful, False otherwise.
        """
        for address in self._get_peer_node_api_addresses():
            vault = VaultClient(address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA))
            if vault.is_active():
                break
        else:
            logger.error("Failed to find active Vault client, cannot restore snapshot.")
            return False
        try:
            if not (approle := self.vault_helpers.get_approle_auth_secret()):
                logger.error("Failed to log in to Vault")
                return False
            vault.authenticate(approle)
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

    def _get_active_vault_client(self) -> VaultClient | None:
        """Return an initialized vault client.

        Returns:
            Vault: An active Vault client configured with the cluster address
                   and CA certificate, and authorized with the AppRole
                   credentials set upon initial authorization of the charm, or
                   `None` if the client could not be successfully created or
                   has not been authorized.
        """
        try:
            vault = VaultClient(
                url=self._api_address,
                ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
            )
        except VaultCertsError as e:
            logger.warning("Failed to get Vault client: %s", e)
            return None
        if not vault.is_api_available():
            return None
        if not (approle := self.vault_helpers.get_approle_auth_secret()):
            return None
        if not vault.authenticate(approle):
            return None
        if not vault.is_active_or_standby():
            return None
        return vault

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
            f"https://{self.app.name}-{i}.{socket.getfqdn().split('.', 1)[-1]}:{VAULT_PORT}"
            for i in range(self.app.planned_units())
        ]

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

    @property
    def _api_address(self) -> str:
        """Return the FQDN with the https schema and vault port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8200"
        """
        return f"https://{socket.getfqdn()}:{VAULT_PORT}"

    @property
    def _cluster_address(self) -> str:
        """Return the FQDN with the https schema and vault cluster port.

        Example: "https://vault-k8s-1.vault-k8s-endpoints.test.svc.cluster.local:8201"
        """
        return f"https://{socket.getfqdn()}:{self.VAULT_CLUSTER_PORT}"


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
