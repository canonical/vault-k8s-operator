#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging
import socket
from typing import Any, List

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.tempo_coordinator_k8s.v0.charm_tracing import trace_charm
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer, charm_tracing_config
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
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
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_helpers import (
    AutounsealConfiguration,
    common_name_config_is_valid,
    config_file_content_matches,
    render_vault_config_file,
    seal_type_has_changed,
)
from charms.vault_k8s.v0.vault_kv import (
    VaultKvClientDetachedEvent,
    VaultKvProvides,
)
from charms.vault_k8s.v0.vault_managers import (
    AutounsealProviderManager,
    AutounsealRequirerManager,
    BackupManager,
    File,
    KVManager,
    ManagerError,
    PKIManager,
    RaftManager,
    TLSManager,
    VaultCertsError,
)
from ops import CharmBase, MaintenanceStatus, main, pebble
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
CHARM_POLICY_NAME = "charm-access"
CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
CONTAINER_NAME = "vault"
CONTAINER_TLS_FILE_DIRECTORY_PATH = "/vault/certs"
KV_RELATION_NAME = "vault-kv"
LOG_FORWARDING_RELATION_NAME = "logging"
PEER_RELATION_NAME = "vault-peers"
PKI_MOUNT = "charm-pki"
PKI_RELATION_NAME = "vault-pki"
PKI_ROLE_NAME = "charm"
PROMETHEUS_ALERT_RULES_PATH = "./src/prometheus_alert_rules"
S3_RELATION_NAME = "s3-parameters"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_CONFIG_FILE_PATH = "/vault/config/vault.hcl"
VAULT_STORAGE_PATH = "/vault/raft"


@trace_charm(
    tracing_endpoint="_tracing_endpoint",
    server_cert="_tracing_server_cert",
    extra_types=(TLSCertificatesProvidesV4,),
)
class VaultCharm(CharmBase):
    """Main class to handle Juju events for the vault-k8s charm."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    def __init__(self, *args: Any):
        super().__init__(*args)
        self.juju_facade = JujuFacade(self)
        self._service_name = self._container_name = CONTAINER_NAME
        self._container = Container(container=self.unit.get_container(self._container_name))
        self.unit.set_ports(self.VAULT_PORT)
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV4(
            charm=self,
            relationship_name=PKI_RELATION_NAME,
        )
        common_name = self.juju_facade.get_string_config("common_name")
        certificate_requests = [self._get_certificate_request(common_name)] if common_name else []
        self.tls_certificates_pki = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
            certificate_requests=certificate_requests,
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
                    "static_configs": [{"targets": [f"*:{self.VAULT_PORT}"]}],
                }
            ],
            alert_rules_path=PROMETHEUS_ALERT_RULES_PATH,
        )
        self._logging = LogForwarder(
            charm=self,
            relation_name=LOG_FORWARDING_RELATION_NAME,
        )
        self.tls = TLSManager(
            charm=self,
            workload=self._container,
            service_name=self._container_name,
            tls_directory_path=CONTAINER_TLS_FILE_DIRECTORY_PATH,
            common_name=self._ingress_address if self._ingress_address else "",
            sans_dns=frozenset([socket.getfqdn()]),
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
            self.on.vault_pki_relation_changed,
            self.on.tls_certificates_pki_relation_joined,
            self.tls_certificates_pki.on.certificate_available,
            self.vault_autounseal_requires.on.vault_autounseal_details_ready,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_created,
            self.vault_autounseal_requires.on.vault_autounseal_provider_relation_broken,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken,
            self.vault_kv.on.new_vault_kv_client_attached,
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
        self.framework.observe(self.on.bootstrap_raft_action, self._on_bootstrap_raft_action)
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
        if self.juju_facade.relation_exists(
            TLS_CERTIFICATES_PKI_RELATION_NAME
        ) and not common_name_config_is_valid(self.juju_facade.get_string_config("common_name")):
            event.add_status(
                BlockedStatus(
                    "Common name is not set in the charm config, cannot configure PKI secrets engine"
                )
            )
            return
        if not self._container.can_connect():
            event.add_status(WaitingStatus("Waiting to be able to connect to vault unit"))
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            event.add_status(WaitingStatus("Waiting for peer relation"))
            return
        if not self._ingress_address:
            event.add_status(WaitingStatus("Waiting for ingress address to be available"))
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
        if not self._get_approle_auth_secret():
            event.add_status(
                BlockedStatus("Please authorize charm (see `authorize-charm` action)")
            )
            return
        self._authenticate_vault_client(vault)
        if not vault.is_active_or_standby():
            event.add_status(WaitingStatus("Waiting for vault to finish raft leader election"))
            return
        event.add_status(ActiveStatus())

    def _configure(self, _: EventBase) -> None:  # noqa: C901
        """Handle config-changed event.

        Configures pebble layer, sets the unit address in the peer relation, starts the vault
        service, and unseals Vault.
        """
        if not self._container.can_connect():
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            return
        if not self._ingress_address:
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
        if not vault.is_available_initialized_and_unsealed():
            return
        if not self._authenticate_vault_client(vault):
            return
        if not vault.is_active_or_standby():
            return
        self._configure_pki_secrets_engine(vault)
        self._sync_vault_autounseal(vault)
        self._sync_vault_kv(vault)
        self._sync_vault_pki(vault)

        if vault.is_active_or_standby() and not vault.is_raft_cluster_healthy():
            # Log if a raft node starts reporting unhealthy
            logger.warning(
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
        vault = VaultClient(url=self._api_address, ca_cert_path=None)
        if not vault.is_available_initialized_and_unsealed():
            return
        self._authenticate_vault_client(vault)
        if vault.is_node_in_raft_peers(self._node_id) and vault.get_num_raft_peers() > 1:
            vault.remove_raft_node(self._node_id)

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        KVManager.remove_unit_credentials(self.juju_facade, event.unit_name)

    def _configure_pki_secrets_engine(self, vault: VaultClient) -> None:
        common_name = self.juju_facade.get_string_config("common_name")
        if not common_name:
            logger.warning("Common name is not set in the charm config")
            return
        manager = PKIManager(
            self,
            vault,
            self._get_certificate_request(common_name),
            PKI_MOUNT,
            PKI_ROLE_NAME,
            self.vault_pki,
            tls_certificates_pki=self.tls_certificates_pki,
        )
        manager.configure()

    def _get_certificate_request(self, common_name: str) -> CertificateRequestAttributes:
        return CertificateRequestAttributes(
            common_name=common_name,
            is_ca=True,
        )

    def _sync_vault_autounseal(self, vault_client: VaultClient) -> None:
        """Sync the vault autounseal relation."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-autounseal request")
            return
        autounseal_provider_manager = AutounsealProviderManager(
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
            relation_address = self._get_relation_api_address(relation)
            if not relation_address:
                logger.warning("Relation address not found for relation %s", relation.id)
                continue
            autounseal_provider_manager.create_credentials(relation, relation_address)
        autounseal_provider_manager.clean_up_credentials()

    def _sync_vault_pki(self, vault: VaultClient) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        common_name = self.juju_facade.get_string_config("common_name")
        if not common_name:
            return
        manager = PKIManager(
            self,
            vault,
            self._get_certificate_request(common_name),
            PKI_MOUNT,
            PKI_ROLE_NAME,
            self.vault_pki,
            tls_certificates_pki=self.tls_certificates_pki,
        )
        manager.sync()

    def _sync_vault_kv(self, vault: VaultClient) -> None:
        """Goes through all the vault-kv relations and sends necessary KV information."""
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        ca_certificate = self.tls.pull_tls_file_from_workload(File.CA)
        if not ca_certificate:
            logger.debug("Vault CA certificate not available")
            return
        manager = KVManager(self, vault, self.vault_kv, ca_certificate)

        kv_requests = self.vault_kv.get_kv_requests()
        for kv_request in kv_requests:
            if not (vault_url := self._get_relation_api_address(kv_request.relation)):
                logger.debug("Failed to get Vault URL for relation %s", kv_request.relation.id)
                continue
            manager.generate_credentials_for_requirer(
                relation=kv_request.relation,
                app_name=kv_request.app_name,
                unit_name=kv_request.unit_name,
                mount_suffix=kv_request.mount_suffix,
                egress_subnets=kv_request.egress_subnets,
                nonce=kv_request.nonce,
                vault_url=vault_url,
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
                logger.warning("Token not found in the secret when authorizing charm.")
                event.fail("Token not found in the secret. Please provide a valid token secret.")
                return
        except (NoSuchSecretError, SecretRemovedError):
            logger.warning(
                "Secret id provided could not be found by the charm when authorizing charm."
            )
            event.fail(
                "The secret id provided could not be found by the charm. Please grant the token secret to the charm."
            )
            return
        vault = VaultClient(self._api_address, self.tls.get_tls_file_path_in_charm(File.CA))
        if not vault.authenticate(Token(token)):
            logger.error("The token provided is not valid when authorizing charm.")
            event.fail(
                "The token provided is not valid. Please use a Vault token with the appropriate permissions."
            )
            return

        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.create_or_update_policy_from_file(name=CHARM_POLICY_NAME, path=CHARM_POLICY_PATH)
            role_id = vault.create_or_update_approle(
                name=APPROLE_ROLE_NAME,
                policies=[CHARM_POLICY_NAME, "default"],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            secret_id = vault.generate_role_secret_id(name=APPROLE_ROLE_NAME)
            self.juju_facade.set_app_secret_content(
                content={"role-id": role_id, "secret-id": secret_id},
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                description="The authentication details for the charm's access to vault.",
            )
            event.set_results(
                {"result": "Charm authorized successfully. You may now remove the secret."}
            )
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")

    def _on_bootstrap_raft_action(self, event: ActionEvent) -> None:
        """Bootstraps the raft cluster when a single node is present.

        This is useful when Vault has lost quorum. The application must first
        be reduced to a single unit.
        """
        try:
            manager = RaftManager(self, self._container, self._service_name, VAULT_STORAGE_PATH)
            manager.bootstrap(self._node_id, self._api_address)
        except ManagerError as e:
            logger.error("Failed to bootstrap raft: %s", e)
            event.fail(message=f"Failed to bootstrap raft: {e}")
            return
        event.set_results({"result": "Raft cluster bootstrapped successfully."})

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handle the create-backup action.

        Creates a snapshot and stores it on S3 storage.
        Outputs the ID of the backup to the user.

        Args:
            event: ActionEvent
        """
        try:
            vault_client = VaultClient(
                url=self._api_address,
                ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
            )
        except VaultCertsError as e:
            logger.warning("Failed to get Vault client: %s", e)
            event.fail(message="Failed to initialize Vault client.")
            return
        if (
            not self._authenticate_vault_client(vault_client)
            or not vault_client.is_active_or_standby()
        ):
            event.fail(message="Failed to initialize Vault client.")
            return
        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            backup_key = manager.create_backup(vault_client)
        except ManagerError as e:
            logger.error("Failed to create backup: %s", e)
            event.fail(message=f"Failed to create backup: {e}")
            return
        event.set_results({"backup-id": backup_key})

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handle the list-backups action.

        Lists all backups stored in S3 bucket.

        Args:
            event: ActionEvent
        """
        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            backup_ids = manager.list_backups()
        except ManagerError as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message=f"Failed to list backups: {e}")
            return

        event.set_results({"backup-ids": json.dumps(backup_ids)})

    def _on_restore_backup_action(self, event: ActionEvent) -> None:
        """Handle the restore-backup action.

        Restores the snapshot with the provided ID.

        Args:
            event: ActionEvent
        """
        vault_client = self._get_active_vault_client()
        if not vault_client:
            event.fail(message="Failed to initialize an active Vault client.")
            return
        key = event.params.get("backup-id")
        # This should be enforced by Juju/charmcraft.yaml, but we assert here
        # to make the typechecker happy
        assert isinstance(key, str)
        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            manager.restore_backup(vault_client, key)
        except ManagerError as e:
            logger.error("Failed to restore backup: %s", e)
            event.fail(message=f"Failed to restore backup: {e}")
            return

        event.set_results({"restored": event.params.get("backup-id")})

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

    def _pebble_plan_is_applied(self) -> bool:
        """Check if the pebble plan is applied."""
        plan = self._container.get_plan()
        layer = self._vault_layer
        return plan.services == layer.services

    def _get_relation_api_address(self, relation: Relation) -> str | None:
        """Fetch the api address from relation and returns it.

        Example: "https://10.152.183.20:8200"
        """
        if not (ingress_address := self.juju_facade.get_ingress_address(relation=relation)):
            return None
        return f"https://{ingress_address}:{self.VAULT_PORT}"

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
            config_template_path=CONFIG_TEMPLATE_DIR_PATH,
            config_template_name=CONFIG_TEMPLATE_NAME,
            default_lease_ttl=self.juju_facade.get_string_config("default_lease_ttl"),
            max_lease_ttl=self.juju_facade.get_string_config("max_lease_ttl"),
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tcp_address=f"[::]:{self.VAULT_PORT}",
            tls_cert_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{CONTAINER_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
            autounseal_config=self._get_vault_autounseal_configuration(),
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
                # Before restarting Vault, check if the pebble plan is applied
                # If the plan was not applied, the service will restart anyway when applying the new plan
                if self._vault_service_is_running() and self._pebble_plan_is_applied():
                    self._container.restart(self._service_name)

    def _get_vault_autounseal_token(self) -> str | None:
        autounseal_relation_details = self.vault_autounseal_requires.get_details()
        if not autounseal_relation_details:
            return None
        autounseal_requirer_manager = AutounsealRequirerManager(
            self, self.vault_autounseal_requires
        )
        provider_vault_token = autounseal_requirer_manager.get_provider_vault_token(
            autounseal_relation_details, self.tls.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA)
        )
        return provider_vault_token

    def _get_vault_autounseal_configuration(self) -> AutounsealConfiguration | None:
        autounseal_relation_details = self.vault_autounseal_requires.get_details()
        if not autounseal_relation_details:
            return None
        self.tls.push_autounseal_ca_cert(autounseal_relation_details.ca_certificate)
        return AutounsealConfiguration(
            autounseal_relation_details.address,
            autounseal_relation_details.mount_path,
            autounseal_relation_details.key_name,
            self.tls.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA),
        )

    def _push_config_file_to_workload(self, content: str):
        """Push the config file to the workload."""
        self._container.push(path=VAULT_CONFIG_FILE_PATH, source=content)
        logger.info("Pushed %s config file", VAULT_CONFIG_FILE_PATH)

    def _get_approle_auth_secret(self) -> AppRole | None:
        """Get the vault approle login details secret.

        Returns:
            AppRole: An AppRole object with role_id and secret_id set from the
                     values stored in the Juju secret, or None if the secret is
                     not found or either of the values are not set.
        """
        try:
            role_id, secret_id = self.juju_facade.get_secret_content_values(
                "role-id", "secret-id", label=VAULT_CHARM_APPROLE_SECRET_LABEL
            )
        except NoSuchSecretError:
            logger.warning("Approle secret not yet created")
            return None
        return AppRole(role_id, secret_id) if role_id and secret_id else None

    def _set_pebble_plan(self) -> None:
        """Set the pebble plan if different from the currently applied one."""
        plan: pebble.Plan = self._container.get_plan()
        layer = self._vault_layer
        if plan.services != layer.services:
            self._container.add_layer(self._container_name, layer, combine=True)
            self._container.replan()
            logger.info("Pebble layer added")

    def _get_active_vault_client(self) -> VaultClient | None:
        """Return a client for the _active_ vault service.

        This may not be the Vault service running on this unit.
        """
        for address in self._get_peer_node_api_addresses():
            try:
                vault = VaultClient(
                    address, ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA)
                )
            except VaultCertsError as e:
                logger.warning("Failed to get Vault client: %s", e)
                continue
            if vault.is_active():
                if not vault.is_api_available():
                    return None
                if not self._authenticate_vault_client(vault):
                    return None
                return vault
        return None

    def _authenticate_vault_client(self, vault: VaultClient) -> bool:
        """Authenticate the Vault client.

        Returns:
            bool: Whether the Vault client authentication was successful.
        """
        if not (approle := self._get_approle_auth_secret()):
            return False
        if not vault.authenticate(approle):
            return False
        return True

    @property
    def _vault_layer(self) -> Layer:
        """Return the pebble layer to start Vault."""
        layer = Layer(
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

        # If we're using autounseal, provide the token to the external vault
        # service (the autounsealer) as an environment variable
        if token := self._get_vault_autounseal_token():
            layer.services["vault"].environment["VAULT_TOKEN"] = token
        return layer

    def _get_peer_node_api_addresses(self) -> List[str]:
        """Return a list of unit addresses that should be a part of the raft cluster."""
        return [
            f"https://{self.app.name}-{i}.{socket.getfqdn().split('.', 1)[-1]}:{self.VAULT_PORT}"
            for i in range(self.app.planned_units())
        ]

    @property
    def _node_id(self) -> str:
        """Return the node id for vault.

        Example of node id: "vault-k8s-0"
        """
        return f"{self.model.name}-{self.unit.name}"

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
    def _ingress_address(self) -> str | None:
        """Fetch the ingress address from peer relation and returns it.

        Returns:
            str: Ingress address
        """
        return self.juju_facade.get_ingress_address(PEER_RELATION_NAME)


if __name__ == "__main__":  # pragma: no cover
    main(VaultCharm)
