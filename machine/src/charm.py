#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import json
import logging
import socket
import subprocess
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v2 import snap
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer
from charms.vault_k8s.v0.vault_kv import VaultKvClientDetachedEvent, VaultKvProvides
from jinja2 import Environment, FileSystemLoader
from ops import ActionEvent, BlockedStatus, ErrorStatus
from ops.charm import CharmBase, CollectStatusEvent, RemoveEvent
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, Relation, WaitingStatus
from vault.juju_facade import JujuFacade, NoSuchSecretError, SecretRemovedError
from vault.vault_autounseal import VaultAutounsealProvides, VaultAutounsealRequires
from vault.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from vault.vault_helpers import (
    AutounsealConfiguration,
    allowed_domains_config_is_valid,
    common_name_config_is_valid,
    config_file_content_matches,
    render_vault_config_file,
    sans_dns_config_is_valid,
    seal_type_has_changed,
)
from vault.vault_managers import (
    TLS_CERTIFICATE_ACCESS_RELATION_NAME,
    TLS_CERTIFICATES_ACME_RELATION_NAME,
    ACMEManager,
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

from machine import Machine
from systemd_creds import SystemdCreds

logger = logging.getLogger(__name__)

ACME_MOUNT = "charm-acme"
ACME_ROLE_NAME = "charm-acme"
AUTOUNSEAL_MOUNT_PATH = "charm-autounseal"
AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"
BACKUP_KEY_PREFIX = "vault-backup"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
INGRESS_RELATION_NAME = "ingress"
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"
MACHINE_TLS_FILE_DIRECTORY_PATH = "/var/snap/vault/common/certs"
METRICS_ALERT_RULES_PATH = "./src/prometheus_alert_rules"
PEER_RELATION_NAME = "vault-peers"
PKI_RELATION_NAME = "vault-pki"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
S3_RELATION_NAME = "s3-parameters"
SYSTEMD_DROP_IN_DIR = "/etc/systemd/system/snap.vault.vaultd.service.d"
SYSTEMD_DROP_IN_FILE_PATH = f"{SYSTEMD_DROP_IN_DIR}/10-charm.conf"
SYSTEMD_CRED_EXTERNAL_VAULT_TOKEN_NAME = "external_vault_token"
TEMPLATE_PATH = "src/templates/"
TEMPLATE_SYSTEMD_DROP_IN_CREDS = "systemd_dropin_creds.conf.j2"
TEMPLATE_SYSTEMD_DROP_IN_ENV = "systemd_dropin_env.conf.j2"
TEMPLATE_VAULT_ENV_LOAD_SYSTEMD_CREDS = "vault_load_systemd_creds.env.j2"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_CHARM_POLICY_NAME = "charm-access"
VAULT_CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
VAULT_CLUSTER_PORT = 8201
VAULT_CONFIG_FILE_NAME = "vault.hcl"
VAULT_CONFIG_PATH = "/var/snap/vault/common"
VAULT_ENV_PATH = f"{VAULT_CONFIG_PATH}/vault.env"
VAULT_DEFAULT_POLICY_NAME = "default"
VAULT_PKI_MOUNT = "charm-pki"
VAULT_PKI_ROLE = "charm-pki"
VAULT_PORT = 8200
VAULT_SNAP_CHANNEL = "1.18/stable"
VAULT_SNAP_NAME = "vault"
VAULT_SNAP_REVISION = "2399"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"


class VaultOperatorCharm(CharmBase):
    """Machine Charm for Vault."""

    def __init__(self, *args: Any):
        super().__init__(*args)
        self.juju_facade = JujuFacade(self)
        self.machine = Machine()
        self._cos_agent = COSAgentProvider(
            self,
            refresh_events=[
                self.on[PEER_RELATION_NAME].relation_changed,
            ],
            scrape_configs=self.generate_vault_scrape_configs,
            dashboard_dirs=["./src/grafana_dashboards"],
            metrics_rules_dir=METRICS_ALERT_RULES_PATH,
        )
        access_sans_dns = self.juju_facade.get_string_config("access_sans_dns")
        access_sans_dns_list = [socket.getfqdn()]
        if access_sans_dns:
            if not sans_dns_config_is_valid(access_sans_dns):
                logger.warning("access_sans_dns is not valid, it must be a comma separated list")
                access_sans_dns_list = []
            else:
                access_sans_dns_list.extend([name.strip() for name in access_sans_dns.split(",")])
        self.tls = TLSManager(
            charm=self,
            workload=self.machine,
            service_name=VAULT_SNAP_NAME,
            tls_directory_path=MACHINE_TLS_FILE_DIRECTORY_PATH,
            common_name=self._bind_address if self._bind_address else "",
            sans_dns=frozenset(access_sans_dns_list),
            sans_ip=frozenset([self._bind_address] if self._bind_address else []),
            country_name=self.juju_facade.get_string_config("access_country_name"),
            state_or_province_name=self.juju_facade.get_string_config(
                "access_state_or_province_name"
            ),
            locality_name=self.juju_facade.get_string_config("access_locality_name"),
            organization=self.juju_facade.get_string_config("access_organization"),
            organizational_unit=self.juju_facade.get_string_config("access_organizational_unit"),
            email_address=self.juju_facade.get_string_config("access_email_address"),
        )
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV4(
            charm=self,
            relationship_name=PKI_RELATION_NAME,
        )
        self.ingress = IngressPerAppRequirer(
            charm=self,
            relation_name=INGRESS_RELATION_NAME,
            port=VAULT_PORT,
            strip_prefix=True,
            scheme=lambda: "https",
            redirect_https=True,
        )
        pki_certificate_request = self._get_pki_certificate_request()
        self.tls_certificates_pki = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
            certificate_requests=[pki_certificate_request] if pki_certificate_request else [],
            mode=Mode.APP,
            refresh_events=[self.on.config_changed],
        )
        acme_certificate_request = self._get_acme_certificate_request()
        self.tls_certificates_acme = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_ACME_RELATION_NAME,
            certificate_requests=[acme_certificate_request] if acme_certificate_request else [],
            mode=Mode.APP,
            refresh_events=[self.on.config_changed],
        )
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.remove, self._on_remove)
        self.vault_autounseal_provides = VaultAutounsealProvides(
            self, AUTOUNSEAL_PROVIDES_RELATION_NAME
        )
        self.vault_autounseal_requires = VaultAutounsealRequires(
            self, AUTOUNSEAL_REQUIRES_RELATION_NAME
        )
        configure_events = [
            self.on.config_changed,
            self.on[PEER_RELATION_NAME].relation_created,
            self.on[PEER_RELATION_NAME].relation_changed,
            self.on.install,
            self.on.update_status,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken,
            self.vault_autounseal_requires.on.vault_autounseal_details_ready,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_created,
            self.vault_autounseal_requires.on.vault_autounseal_provider_relation_broken,
            self.tls_certificates_pki.on.certificate_available,
            self.on.tls_certificates_pki_relation_joined,
            self.on.vault_pki_relation_changed,
            self.vault_kv.on.new_vault_kv_client_attached,
        ]
        for event in configure_events:
            self.framework.observe(event, self._configure)
        self.framework.observe(
            self.vault_kv.on.vault_kv_client_detached, self._on_vault_kv_client_detached
        )

        # Actions
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)
        self.framework.observe(self.on.bootstrap_raft_action, self._on_bootstrap_raft_action)
        self.framework.observe(self.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.on.restore_backup_action, self._on_restore_backup_action)

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        KVManager.remove_unit_credentials(self.juju_facade, event.unit_name)

    def _get_active_vault_client(self) -> VaultClient | None:
        """Return a client for the _active_ vault service.

        This may not be the Vault service running on this unit.
        """
        addresses = self._get_peer_relation_node_api_addresses()
        for address in addresses:
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
                if not (approle := self._get_vault_approle_secret()):
                    return None
                if not vault.authenticate(approle):
                    return None
                return vault
        return None

    def _get_authenticated_vault_client(self) -> VaultClient | None:
        """Return an authenticate vault client.

        Returns:
            Vault: An active Vault client configured with the cluster address
                   and CA certificate, and authorized with the AppRole
                   credentials set upon initial authorization of the charm, or
                   `None` if the client could not be successfully created or
                   has not been authorized.
        """
        vault = self._get_vault_client()
        if not vault:
            return None
        if not vault.is_api_available():
            return None
        approle = self._get_vault_approle_secret()
        if not approle:
            return None
        if not vault.authenticate(approle):
            return None
        if not vault.is_active_or_standby():
            return None
        return vault

    def _sync_vault_autounseal(self, vault_client: VaultClient) -> None:
        """Go through all the vault-autounseal relations and send necessary credentials.

        This looks for any outstanding requests for auto-unseal that may have
        been missed. If there are any, it generates the credentials and sets
        them in the relation databag.
        """
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

    def generate_vault_scrape_configs(self) -> List[Dict] | None:
        """Generate the scrape configs for the COS agent.

        Returns:
            The scrape configs for the COS agent or an empty list.
        """
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            return []
        return [
            {
                "scheme": "https",
                "tls_config": {
                    "insecure_skip_verify": False,
                    "ca": self.tls.pull_tls_file_from_workload(File.CA),
                },
                "metrics_path": "/v1/sys/metrics",
                "static_configs": [{"targets": [f"{self._bind_address}:{VAULT_PORT}"]}],
            }
        ]

    @contextmanager
    def temp_maintenance_status(self, message: str):
        """Context manager to set the charm status temporarily.

        Useful around long-running operations to indicate that the charm is
        busy.
        """
        previous_status = self.unit.status
        self.unit.status = MaintenanceStatus(message)
        yield
        self.unit.status = previous_status

    def _on_authorize_charm_action(self, event: ActionEvent):
        """Authorize the charm to interact with Vault."""
        if not self.unit.is_leader():
            event.fail("This action can only be run by the leader unit")
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

        logger.info("Authorizing the charm to interact with Vault")
        if not self._api_address:
            logger.warning("API address is not available when authorizing charm")
            event.fail("API address is not available.")
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.fail("CA certificate is not available in the charm. Something is wrong.")
            return
        vault = self._get_vault_client()
        if not vault:
            logger.warning("Failed to initialize the Vault client when authorizing charm")
            event.fail("Failed to initialize the Vault client")
            return
        if not vault.authenticate(Token(token)):
            logger.warning("Failed to authenticate with Vault when authorizing charm")
            event.fail("Failed to authenticate with Vault")
            return
        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.create_or_update_policy_from_file(
                name=VAULT_CHARM_POLICY_NAME, path=VAULT_CHARM_POLICY_PATH
            )
            role_id = vault.create_or_update_approle(
                name="charm",
                policies=[VAULT_CHARM_POLICY_NAME, VAULT_DEFAULT_POLICY_NAME],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            vault_secret_id = vault.generate_role_secret_id(name="charm")
            self.juju_facade.set_app_secret_content(
                content={"role-id": role_id, "secret-id": vault_secret_id},
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                description="The authentication details for the charm's access to vault.",
            )
            event.set_results(
                {"result": "Charm authorized successfully. You may now remove the secret."}
            )
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")
            return

    def _on_bootstrap_raft_action(self, event: ActionEvent):
        """Bootstraps the raft cluster when a single node is present.

        This is useful when Vault has lost quorum. The application must first
        be reduced to a single unit.
        """
        if not self._api_address:
            event.fail(message="Network bind address is not available")
            return

        try:
            manager = RaftManager(self, self.machine, VAULT_SNAP_NAME, VAULT_STORAGE_PATH)
            manager.bootstrap(self._node_id, self._api_address)
        except ManagerError as e:
            logger.error("Failed to bootstrap raft: %s", e)
            event.fail(message=f"Failed to bootstrap raft: {e}")
            return
        event.set_results({"result": "Raft cluster bootstrapped successfully."})

    def _get_vault_client(self) -> VaultClient | None:
        if not self._api_address:
            return None
        if not self.tls.tls_file_available_in_charm(File.CA):
            return None
        return VaultClient(
            url=self._api_address,
            ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
        )

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa: C901
        """Handle the collect status event."""
        if self.juju_facade.relation_exists(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            if not sans_dns_config_is_valid(self.juju_facade.get_string_config("access_sans_dns")):
                event.add_status(
                    BlockedStatus(
                        "Config value for access_sans_dns is not valid, it must be a comma separated list"
                    )
                )
                return
        if self.juju_facade.relation_exists(PKI_RELATION_NAME):
            if not self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
                event.add_status(
                    BlockedStatus(
                        f"{TLS_CERTIFICATES_PKI_RELATION_NAME} relation is missing, cannot configure PKI secrets engine"
                    )
                )
                return
        if self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            if not common_name_config_is_valid(
                self.juju_facade.get_string_config("pki_ca_common_name")
            ):
                event.add_status(
                    BlockedStatus(
                        "pki_ca_common_name is not set in the charm config, cannot configure PKI secrets engine"
                    )
                )
                return
            if not allowed_domains_config_is_valid(
                self.juju_facade.get_string_config("pki_allowed_domains")
            ):
                event.add_status(
                    BlockedStatus(
                        "Config value for pki_allowed_domains is not valid, it must be a comma separated list"
                    )
                )
                return
            if not sans_dns_config_is_valid(self.juju_facade.get_string_config("pki_ca_sans_dns")):
                event.add_status(
                    BlockedStatus(
                        "Config value for pki_ca_sans_dns is not valid, it must be a comma separated list"
                    )
                )
                return
        if self.juju_facade.relation_exists(TLS_CERTIFICATES_ACME_RELATION_NAME):
            if not common_name_config_is_valid(
                self.juju_facade.get_string_config("acme_ca_common_name")
            ):
                event.add_status(
                    BlockedStatus(
                        "acme_ca_common_name is not set in the charm config, cannot configure ACME server"
                    )
                )
                return
            if not allowed_domains_config_is_valid(
                self.juju_facade.get_string_config("acme_allowed_domains")
            ):
                event.add_status(
                    BlockedStatus(
                        "Config value for acme_allowed_domains is not valid, it must be a comma separated list"
                    )
                )
                return
            if not sans_dns_config_is_valid(
                self.juju_facade.get_string_config("acme_ca_sans_dns")
            ):
                event.add_status(
                    BlockedStatus(
                        "Config value for acme_ca_sans_dns is not valid, it must be a comma separated list"
                    )
                )
                return

        if not self._log_level_is_valid(self._get_log_level()):
            event.add_status(BlockedStatus("log_level config is not valid"))
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            event.add_status(WaitingStatus("Waiting for peer relation"))
            return
        if not self._bind_address:
            event.add_status(WaitingStatus("Waiting for bind address"))
            return
        if not self.unit.is_leader() and len(self._other_peer_node_api_addresses()) == 0:
            event.add_status(WaitingStatus("Waiting for other units to provide their addresses"))
            return
        if not self.tls.tls_file_pushed_to_workload(File.CA):
            event.add_status(WaitingStatus("Waiting for CA certificate in workload"))
            return
        if not self._api_address:
            event.add_status(WaitingStatus("No address received from Juju yet"))
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.add_status(WaitingStatus("Certificate is unavailable in the charm"))
            return
        if not self._is_vault_service_started():
            event.add_status(WaitingStatus("Waiting for Vault service to start"))
            return
        vault = self._get_vault_client()
        if not vault:
            event.add_status(ErrorStatus("Failed to initialize the Vault client"))
            return
        if not vault.is_api_available():
            event.add_status(WaitingStatus("Vault API is not yet available"))
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
        if not self._get_vault_approle_secret():
            event.add_status(
                BlockedStatus("Please authorize charm (see `authorize-charm` action)")
            )
            return
        event.add_status(ActiveStatus())

    def _configure(self, _):  # noqa: C901
        """Handle Vault installation.

        This includes:
          - Installing the Vault snap
          - Generating the Vault config file
        """
        self._create_backend_directory()
        self._create_certs_directory()
        try:
            self._install_vault_snap()
        except snap.SnapError as e:
            logger.error("Failed to install Vault snap: %s", e)
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            return
        if not self._bind_address:
            return
        if not self.juju_facade.is_leader:
            if len(self._other_peer_node_api_addresses()) == 0:
                return
            if not self.tls.ca_certificate_is_saved():
                return
        if not self._log_level_is_valid(self._get_log_level()):
            return
        self._generate_vault_config_file()
        try:
            self._start_vault_service()
        except snap.SnapError as e:
            logger.error("Failed to start Vault service: %s", e)
            return
        self._set_peer_relation_node_api_address()

        vault = self._get_authenticated_vault_client()
        if not vault:
            return
        self._configure_pki_secrets_engine(vault)
        self._configure_acme_server(vault)
        self._sync_vault_autounseal(vault)
        self._sync_vault_kv(vault)
        self._sync_vault_pki(vault)

        if not self._api_address or not self.tls.tls_file_available_in_charm(File.CA):
            return

        if vault.is_active() and not vault.is_raft_cluster_healthy():
            logger.warning("Raft cluster is not healthy: %s", vault.get_raft_cluster_state())

    def _on_remove(self, event: RemoveEvent):
        """Handle remove charm event.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        self._remove_node_from_raft_cluster()
        if self._vault_service_is_running():
            self.machine.stop(VAULT_SNAP_NAME)
        self._delete_vault_data()

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handle the create-backup action.

        Creates a snapshot and stores it on S3 storage.
        Outputs the ID of the backup to the user.

        Args:
            event: ActionEvent
        """
        skip_verify: bool = event.params.get("skip-verify", False)

        vault_client = self._get_authenticated_vault_client()
        if not vault_client:
            event.fail(message="Failed to initialize Vault client.")
            return
        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            backup_key = manager.create_backup(vault_client, skip_verify=skip_verify)
        except ManagerError as e:
            logger.error("Failed to create backup: %s", e)
            event.fail(message=f"Failed to create backup: {e}")
            return
        event.set_results({"backup-id": backup_key})

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handle the list-backups action.

        Lists all backups stored in S3 bucket.
        """
        skip_verify: bool = event.params.get("skip-verify", False)

        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            backup_ids = manager.list_backups(skip_verify=skip_verify)
        except ManagerError as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message=f"Failed to list backups: {e}")
            return

        event.set_results({"backup-ids": json.dumps(backup_ids)})

    def _on_restore_backup_action(self, event: ActionEvent) -> None:
        """Handle the restore-backup action.

        Restores the snapshot with the provided ID.
        """
        vault_client = self._get_active_vault_client()
        if not vault_client:
            event.fail(message="Failed to initialize an active Vault client.")
            return
        key = event.params.get("backup-id")
        # This should be enforced by Juju/charmcraft.yaml, but we assert here
        # to make the typechecker happy
        assert isinstance(key, str)
        skip_verify: bool = event.params.get("skip-verify", False)

        try:
            manager = BackupManager(self, self.s3_requirer, S3_RELATION_NAME)
            manager.restore_backup(vault_client, key, skip_verify=skip_verify)
        except ManagerError as e:
            logger.error("Failed to restore backup: %s", e)
            event.fail(message=f"Failed to restore backup: {e}")
            return

        event.set_results({"restored": event.params.get("backup-id")})

    def _vault_service_is_running(self) -> bool:
        """Check if the Vault service is running."""
        service = self.machine.get_service(process=VAULT_SNAP_NAME)
        return False if not service else service.is_running()

    def _delete_vault_data(self) -> None:
        """Delete Vault's data."""
        try:
            self.machine.remove_path(path=f"{VAULT_STORAGE_PATH}/vault.db")
            logger.info("Removed Vault's main database")
        except ValueError:
            logger.info("No Vault database to remove")
        try:
            self.machine.remove_path(path=f"{VAULT_STORAGE_PATH}/raft/raft.db")
            logger.info("Removed Vault's Raft database")
        except ValueError:
            logger.info("No Vault raft database to remove")

    def _remove_node_from_raft_cluster(self):
        """Remove the node from the raft cluster."""
        if not (approle := self._get_vault_approle_secret()):
            logger.error("Failed to authenticate to Vault")
            return
        api_address = self._api_address
        if not api_address:
            logger.error("Can't remove node from cluster - Vault API address is not available")
            return
        vault = VaultClient(url=api_address, ca_cert_path=None)
        if not vault.is_api_available():
            logger.error("Can't remove node from cluster - Vault API is not available")
            return
        if not vault.is_initialized():
            logger.error("Can't remove node from cluster - Vault is not initialized")
            return
        try:
            if vault.is_sealed():
                logger.error("Can't remove node from cluster - Vault is sealed")
                return
        except VaultClientError as e:
            logger.error("Can't remove node from cluster - Vault status check failed: %s", e)
            return
        vault.authenticate(approle)
        if vault.is_node_in_raft_peers(id=self._node_id) and vault.get_num_raft_peers() > 1:
            vault.remove_raft_node(id=self._node_id)

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

    def _get_missing_s3_parameters(self) -> List[str]:
        """Return the list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        return [param for param in REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _get_relation_api_address(self, relation: Relation) -> str:
        """Get the API address for the given relation."""
        ingress_address = self.juju_facade.get_ingress_address(relation=relation)
        return f"https://{ingress_address}:{VAULT_PORT}"

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

    def _sync_vault_pki(self, vault_client: VaultClient) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        if not common_name_config_is_valid(
            self.juju_facade.get_string_config("pki_ca_common_name")
        ):
            return
        if not allowed_domains_config_is_valid(
            self.juju_facade.get_string_config("pki_ca_allowed_domains")
        ):
            return
        if not sans_dns_config_is_valid(self.juju_facade.get_string_config("pki_ca_sans_dns")):
            return
        certificate_request = self._get_pki_certificate_request()
        if not certificate_request:
            return
        manager = PKIManager(
            charm=self,
            vault_client=vault_client,
            certificate_request_attributes=certificate_request,
            mount_point=VAULT_PKI_MOUNT,
            role_name=VAULT_PKI_ROLE,
            vault_pki=self.vault_pki,
            tls_certificates_pki=self.tls_certificates_pki,
            allowed_domains=self.juju_facade.get_string_config("pki_allowed_domains"),
            allow_subdomains=self.juju_facade.get_bool_config("pki_allow_subdomains"),
            allow_wildcard_certificates=self.juju_facade.get_bool_config(
                "pki_allow_wildcard_certificates"
            ),
            allow_any_name=self.juju_facade.get_bool_config("pki_allow_any_name"),
            allow_ip_sans=self.juju_facade.get_bool_config("pki_allow_ip_sans"),
            organization=self.juju_facade.get_string_config("pki_organization"),
            organizational_unit=self.juju_facade.get_string_config("pki_organizational_unit"),
            country=self.juju_facade.get_string_config("pki_country"),
            province=self.juju_facade.get_string_config("pki_province"),
            locality=self.juju_facade.get_string_config("pki_locality"),
        )
        manager.sync()

    def _configure_pki_secrets_engine(self, vault: VaultClient) -> None:  # noqa: C901
        """Configure the PKI secrets engine."""
        if not common_name_config_is_valid(
            self.juju_facade.get_string_config("pki_ca_common_name")
        ):
            logger.warning(
                "pki_ca_common_name is not set in the charm config, not configuring PKI secrets engine"
            )
            return
        if not allowed_domains_config_is_valid(
            self.juju_facade.get_string_config("pki_allowed_domains")
        ):
            logger.warning(
                "pki_ca_allowed_domains has invalid value, must be a comma separated list, skipping PKI secrets engine configuration"
            )
            return
        if not sans_dns_config_is_valid(self.juju_facade.get_string_config("pki_ca_sans_dns")):
            logger.warning(
                "pki_ca_sans_dns has invalid value, must be a comma separated list, skipping PKI secrets engine configuration"
            )
            return
        certificate_request = self._get_pki_certificate_request()
        if not certificate_request:
            return
        manager = PKIManager(
            charm=self,
            vault_client=vault,
            certificate_request_attributes=certificate_request,
            mount_point=VAULT_PKI_MOUNT,
            role_name=VAULT_PKI_ROLE,
            tls_certificates_pki=self.tls_certificates_pki,
            vault_pki=self.vault_pki,
            allowed_domains=self.juju_facade.get_string_config("pki_allowed_domains"),
            allow_subdomains=self.juju_facade.get_bool_config("pki_allow_subdomains"),
            allow_wildcard_certificates=self.juju_facade.get_bool_config(
                "pki_allow_wildcard_certificates"
            ),
            allow_any_name=self.juju_facade.get_bool_config("pki_allow_any_name"),
            allow_ip_sans=self.juju_facade.get_bool_config("pki_allow_ip_sans"),
            organization=self.juju_facade.get_string_config("pki_organization"),
            organizational_unit=self.juju_facade.get_string_config("pki_organizational_unit"),
            country=self.juju_facade.get_string_config("pki_country"),
            province=self.juju_facade.get_string_config("pki_province"),
            locality=self.juju_facade.get_string_config("pki_locality"),
        )
        manager.configure()

    def _get_pki_certificate_request(self) -> CertificateRequestAttributes | None:
        common_name = self.juju_facade.get_string_config("pki_ca_common_name")
        if not common_name:
            logger.warning("pki_ca_common_name is not set in the charm config")
            return None
        sans_dns = self.juju_facade.get_string_config("pki_ca_sans_dns")
        if not sans_dns_config_is_valid(sans_dns):
            logger.warning("pki_ca_sans_dns is not valid")
            return None
        if sans_dns:
            sans_dns = [name.strip() for name in sans_dns.split(",")]
        return CertificateRequestAttributes(
            common_name=common_name,
            sans_dns=frozenset(sans_dns) if sans_dns else frozenset(),
            country_name=self.juju_facade.get_string_config("pki_ca_country_name")
            if self.juju_facade.get_string_config("pki_ca_country_name")
            else None,
            state_or_province_name=self.juju_facade.get_string_config(
                "pki_ca_state_or_province_name"
            )
            if self.juju_facade.get_string_config("pki_ca_state_or_province_name")
            else None,
            locality_name=self.juju_facade.get_string_config("pki_ca_locality_name")
            if self.juju_facade.get_string_config("pki_ca_locality_name")
            else None,
            organization=self.juju_facade.get_string_config("pki_ca_organization")
            if self.juju_facade.get_string_config("pki_ca_organization")
            else None,
            organizational_unit=self.juju_facade.get_string_config("pki_ca_organizational_unit")
            if self.juju_facade.get_string_config("pki_ca_organizational_unit")
            else None,
            email_address=self.juju_facade.get_string_config("pki_ca_email_address")
            if self.juju_facade.get_string_config("pki_ca_email_address")
            else None,
            is_ca=True,
        )

    def _configure_acme_server(self, vault: VaultClient) -> None:
        if not common_name_config_is_valid(
            self.juju_facade.get_string_config("acme_ca_common_name")
        ):
            logger.warning(
                "acme_ca_common_name has invalid value, skipping ACME server configuration"
            )
            return
        if not allowed_domains_config_is_valid(
            self.juju_facade.get_string_config("acme_allowed_domains")
        ):
            logger.warning(
                "acme_allowed_domains has invalid value, must be a comma separated list, skipping PKI secrets engine configuration"
            )
            return
        if not sans_dns_config_is_valid(self.juju_facade.get_string_config("acme_ca_sans_dns")):
            logger.warning(
                "acme_ca_sans_dns has invalid value, must be a comma separated list, skipping PKI secrets engine configuration"
            )
            return
        certificate_request = self._get_acme_certificate_request()
        if not certificate_request:
            return
        manager = ACMEManager(
            charm=self,
            vault_client=vault,
            mount_point=ACME_MOUNT,
            tls_certificates_acme=self.tls_certificates_acme,
            certificate_request_attributes=certificate_request,
            role_name=ACME_ROLE_NAME,
            vault_address=f"https://{self._ingress_address}:{VAULT_PORT}",
            allowed_domains=self.juju_facade.get_string_config("acme_allowed_domains"),
            allow_subdomains=self.juju_facade.get_bool_config("acme_allow_subdomains"),
            allow_wildcard_certificates=self.juju_facade.get_bool_config(
                "acme_allow_wildcard_certificates"
            ),
            allow_any_name=self.juju_facade.get_bool_config("acme_allow_any_name"),
            allow_ip_sans=self.juju_facade.get_bool_config("acme_allow_ip_sans"),
            organization=self.juju_facade.get_string_config("acme_organization"),
            organizational_unit=self.juju_facade.get_string_config("acme_organizational_unit"),
            country=self.juju_facade.get_string_config("acme_country"),
            province=self.juju_facade.get_string_config("acme_province"),
            locality=self.juju_facade.get_string_config("acme_locality"),
        )
        manager.configure()

    def _get_acme_certificate_request(self) -> CertificateRequestAttributes | None:
        common_name = self.juju_facade.get_string_config("acme_ca_common_name")
        if not common_name:
            logger.warning("acme_ca_common_name is not set in the charm config")
            return None
        sans_dns = self.juju_facade.get_string_config("acme_ca_sans_dns")
        if not sans_dns_config_is_valid(sans_dns):
            logger.warning("acme_ca_sans_dns is not valid")
            return None
        if sans_dns:
            sans_dns = [name.strip() for name in sans_dns.split(",")]
        return CertificateRequestAttributes(
            common_name=common_name,
            sans_dns=frozenset(sans_dns) if sans_dns else frozenset(),
            country_name=self.juju_facade.get_string_config("acme_ca_country_name")
            if self.juju_facade.get_string_config("acme_ca_country_name")
            else None,
            state_or_province_name=self.juju_facade.get_string_config(
                "acme_ca_state_or_province_name"
            )
            if self.juju_facade.get_string_config("acme_ca_state_or_province_name")
            else None,
            locality_name=self.juju_facade.get_string_config("acme_ca_locality_name")
            if self.juju_facade.get_string_config("acme_ca_locality_name")
            else None,
            organization=self.juju_facade.get_string_config("acme_ca_organization")
            if self.juju_facade.get_string_config("acme_ca_organization")
            else None,
            organizational_unit=self.juju_facade.get_string_config("acme_ca_organizational_unit")
            if self.juju_facade.get_string_config("acme_ca_organizational_unit")
            else None,
            email_address=self.juju_facade.get_string_config("acme_ca_email_address")
            if self.juju_facade.get_string_config("acme_ca_email_address")
            else None,
            is_ca=True,
        )

    def _get_default_lease_ttl(self) -> str:
        """Return the default lease ttl config."""
        default_lease_ttl = self.config.get("default_lease_ttl")
        if not default_lease_ttl or not isinstance(default_lease_ttl, str):
            raise ValueError("Invalid config default_lease_ttl")
        return default_lease_ttl

    def _get_max_lease_ttl(self) -> str:
        """Return the max lease ttl config."""
        max_lease_ttl = self.config.get("max_lease_ttl")
        if not max_lease_ttl or not isinstance(max_lease_ttl, str):
            raise ValueError("Invalid config max_lease_ttl")
        return max_lease_ttl

    def _get_log_level(self) -> str:
        """Return the log level config."""
        log_level = self.config.get("log_level")
        if not log_level or not isinstance(log_level, str):
            raise ValueError("Invalid config log_level")
        return log_level

    def _log_level_is_valid(self, log_level: str) -> bool:
        return log_level in ["trace", "debug", "info", "warn", "error"]

    def _get_vault_approle_secret(self) -> AppRole | None:
        """Get the approle details from the secret.

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

    def _install_vault_snap(self) -> None:
        """Installs the Vault snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            vault_snap = snap_cache[VAULT_SNAP_NAME]
            if VAULT_SNAP_REVISION == vault_snap.revision and vault_snap.state in [
                snap.SnapState.Latest,
                snap.SnapState.Present,
            ]:
                logger.debug("Vault snap revision %s is already installed", VAULT_SNAP_REVISION)
                return
            with self.temp_maintenance_status("Installing Vault"):
                vault_snap.ensure(
                    snap.SnapState.Latest, channel=VAULT_SNAP_CHANNEL, revision=VAULT_SNAP_REVISION
                )
                vault_snap.hold()
            logger.info("Vault snap installed")
            if self._vault_service_is_running():
                self.machine.stop(VAULT_SNAP_NAME)
                logger.debug("Previously running Vault service stopped")
        except snap.SnapError as e:
            logger.error("An exception occurred when installing Vault. Reason: %s", str(e))
            raise e

    def _create_backend_directory(self) -> None:
        self.machine.make_dir(path=VAULT_STORAGE_PATH)

    def _create_certs_directory(self) -> None:
        self.machine.make_dir(path=MACHINE_TLS_FILE_DIRECTORY_PATH)

    def _start_vault_service(self) -> None:
        """Start the Vault service."""
        self._sync_autounseal_token_with_systemd()

        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[VAULT_SNAP_NAME]
        vault_snap.start(services=["vaultd"])
        logger.debug("Vault service started")

    def _sync_autounseal_token_with_systemd(self) -> None:
        """Add or remove the systemd drop-in file for the Vault service.

        This file is used to set the VAULT_TOKEN environment variable for the
        external Vault service when using auto-unseal.

        If no token is available, the file is removed.
        """
        token = self._get_vault_autounseal_token()
        if not token:
            logger.debug("No auto-unseal token available")
            try:
                self.machine.remove_path(SYSTEMD_DROP_IN_FILE_PATH)
                self.machine.remove_path(VAULT_ENV_PATH)
                logger.info("Removed systemd drop-in file since token is no longer set")
            except ValueError:
                pass
            return

        try:
            SystemdCreds.encrypt_if_changed(SYSTEMD_CRED_EXTERNAL_VAULT_TOKEN_NAME, token)
        except subprocess.CalledProcessError:
            logger.warning("Failed to encrypt auto-unseal token")

        if self._generate_systemd_drop_in_file(token):
            SystemdCreds.reload_daemon()

    def _generate_systemd_drop_in_file(self, external_vault_token: str) -> bool:
        """Create the systemd drop-in file for the Vault service.

        This file is a bit like an overlay, and adds some extra configuration
        to a service. In particular, we use this file to pass the encrypted
        external vault token to the service (if supported), or otherwise inject
        the token as an environment variable.

        If the token is passed via a credential, we also update the `vault.env`
        file to load this credential into the VAULT_TOKEN env var.

        Returns:
            True if the file was created, False otherwise
        """
        jinja2 = Environment(loader=FileSystemLoader(TEMPLATE_PATH))
        self.machine.make_dir(path=SYSTEMD_DROP_IN_DIR)

        if SystemdCreds.is_credentials_supported():
            if self.machine.exists(path=SYSTEMD_DROP_IN_FILE_PATH):
                return False

            dropin_content = jinja2.get_template(TEMPLATE_SYSTEMD_DROP_IN_CREDS).render(
                credential_name=SYSTEMD_CRED_EXTERNAL_VAULT_TOKEN_NAME
            )
            self.machine.push(path=SYSTEMD_DROP_IN_FILE_PATH, source=dropin_content)
            # Use the vault.env file to load the credential into an environment
            # variable.
            # NOTE: In Vault 1.19, we can remove this and load the token
            # directly from a file.
            vault_env_content = jinja2.get_template(TEMPLATE_VAULT_ENV_LOAD_SYSTEMD_CREDS).render(
                credential_name=SYSTEMD_CRED_EXTERNAL_VAULT_TOKEN_NAME
            )
            self.machine.push(path=VAULT_ENV_PATH, source=vault_env_content)
            logger.info("Created systemd drop-in file for Vault service")
        else:
            # If credentials are not working, pass the token via an env var
            logger.warning(
                "This system configuration does not support systemd credentials. Falling back to un-encrypted environment variables."
            )
            dropin_content = jinja2.get_template(TEMPLATE_SYSTEMD_DROP_IN_ENV).render(
                external_vault_token=external_vault_token
            )
            self.machine.push(path=SYSTEMD_DROP_IN_FILE_PATH, source=dropin_content)
        return True

    def _generate_vault_config_file(self) -> None:
        """Create the Vault config file and push it to the Machine."""
        assert self._cluster_address
        assert self._api_address
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
                "leader_ca_cert_file": f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",  # noqa: E501
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]

        autounseal_configuration_details = self._get_vault_autounseal_configuration()

        content = render_vault_config_file(
            config_template_path=TEMPLATE_PATH,
            config_template_name=CONFIG_TEMPLATE_NAME,
            default_lease_ttl=self._get_default_lease_ttl(),
            max_lease_ttl=self._get_max_lease_ttl(),
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tls_cert_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
            tcp_address=f"[::]:{VAULT_PORT}",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
            autounseal_config=autounseal_configuration_details,
            log_level=self._get_log_level(),
        )
        existing_content = ""
        vault_config_file_path = f"{VAULT_CONFIG_PATH}/{VAULT_CONFIG_FILE_NAME}"
        if self.machine.exists(path=vault_config_file_path):
            existing_content_stringio = self.machine.pull(path=vault_config_file_path)
            existing_content = existing_content_stringio.read()

        if not config_file_content_matches(existing_content=existing_content, new_content=content):
            self.machine.push(
                path=vault_config_file_path,
                source=content,
            )
            # If the seal type has changed, we need to restart Vault to apply
            # the changes. SIGHUP is currently only supported as a beta feature
            # for the enterprise version in Vault 1.16+
            if seal_type_has_changed(existing_content, content):
                self._restart_vault_service()

    def _restart_vault_service(self) -> None:
        """Restart the Vault service."""
        if self._vault_service_is_running():
            self._sync_autounseal_token_with_systemd()
            self.machine.restart(VAULT_SNAP_NAME)
            logger.debug("Vault service restarted")

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

    def _set_peer_relation_node_api_address(self) -> None:
        """Set the unit address in the peer relation."""
        assert self._api_address
        self.juju_facade.set_unit_relation_data(
            data={"node_api_address": self._api_address},
            name=PEER_RELATION_NAME,
        )

    def _get_peer_relation_node_api_addresses(self) -> List[str]:
        """Return the list of peer unit addresses."""
        peer_relation_data = self.juju_facade.get_remote_units_relation_data(
            name=PEER_RELATION_NAME,
        )
        return [
            databag["node_api_address"]
            for databag in peer_relation_data
            if "node_api_address" in databag
        ] + ([self._api_address] if self._api_address else [])

    def _other_peer_node_api_addresses(self) -> List[str]:
        """Return the list of other peer unit addresses.

        We exclude our own unit address from the list.
        """
        return [
            node_api_address
            for node_api_address in self._get_peer_relation_node_api_addresses()
            if node_api_address != self._api_address
        ]

    def _is_vault_service_started(self) -> bool:
        """Check if the Vault service is started."""
        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[VAULT_SNAP_NAME]
        vault_services = vault_snap.services
        vaultd_service = vault_services.get("vaultd")
        if not vaultd_service:
            return False
        if not vaultd_service["active"]:
            return False
        return True

    @property
    def _bind_address(self) -> str | None:
        """Fetches bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        return self.juju_facade.get_bind_address(relation_name=PEER_RELATION_NAME)

    @property
    def _api_address(self) -> str | None:
        """Returns the IP with the https schema and vault port.

        Example: "https://1.2.3.4:8200"
        """
        if not self._bind_address:
            return None
        return f"https://{self._bind_address}:{VAULT_PORT}"

    @property
    def _cluster_address(self) -> str | None:
        """Return the IP with the https schema and vault port.

        Example: "https://1.2.3.4:8201"
        """
        if not self._bind_address:
            return None
        return f"https://{self._bind_address}:{VAULT_CLUSTER_PORT}"

    @property
    def _node_id(self) -> str:
        """Return node id for vault.

        Example of node id: "vault-0"
        """
        return f"{self.model.name}-{self.unit.name}"

    @property
    def _ingress_address(self) -> str | None:
        """Fetch the ingress address from peer relation and returns it.

        Returns:
            str: Ingress address
        """
        return self.juju_facade.get_ingress_address(PEER_RELATION_NAME)


if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
