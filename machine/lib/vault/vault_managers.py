"""Library for managing Vault Charm features.

This library encapsulates the business logic for managing the Vault service and
its associated integrations within the context of our charms.

A Vault Feature Manager will aim to encapsulate as much of the business logic
related to the implementation of a specific feature as reasonably possible.

A feature, in this context, is any set of related concepts which distinctly
enhance the offering of the Charm by interacting with the Vault Service to
perform related operations. A feature may be optional, or required. Features
include TLS support, PKI and KV backends, and Auto-unseal.

Feature managers should:

- Abstract away any implementation specific details such as policy and mount
  names.
- Provide a simple interface for the charm to ensure the feature is correctly
  configured given the state of the charm. Ideally, this is a single method
  called `sync()`.
- Be idempotent.
- Be infrastructure dependent (i.e. no Kubernetes or Machine specific code).
- Catch all expected exceptions, and prevent them from reaching the Charm.

Feature managers should not:

- Be concerned with the charm's lifecycle (i.e. Charm status)
- Depend on each other unless the features explicitly require the dependency.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import FrozenSet, MutableMapping, TextIO

from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    TLSCertificatesError,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from vault.juju_facade import (
    FacadeError,
    JujuFacade,
    NoSuchSecretError,
    NoSuchStorageError,
    TransientJujuError,
)
from vault.vault_autounseal import (
    AutounsealDetails,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from vault.vault_client import (
    AppRole,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_kv import VaultKvProvides
from vault.vault_s3 import S3, S3Error
from ops import CharmBase, EventBase, Object, Relation
from ops.pebble import PathError


SEND_CA_CERT_RELATION_NAME = "send-ca-cert"
TLS_CERTIFICATE_ACCESS_RELATION_NAME = "tls-certificates-access"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "self-signed-vault-ca-certificate"

VAULT_CA_SUBJECT = "Vault self signed CA"
AUTOUNSEAL_POLICY = """path "{mount}/encrypt/{key_name}" {{
    capabilities = ["update"]
}}

path "{mount}/decrypt/{key_name}" {{
    capabilities = ["update"]
}}
"""

KV_POLICY = """# Allows the KV requirer to create, read, update, delete and list secrets
path "{mount}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
path "sys/internal/ui/mounts/{mount}" {{
  capabilities = ["read"]
}}
"""


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_managers"

    def process(self, msg: str, kwargs: MutableMapping) -> tuple[str, MutableMapping]:
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})


class ManagerError(Exception):
    """Exception raised when a manager encounters an error."""

    pass


class TLSMode(Enum):
    """This class defines the different modes of TLS configuration.

    SELF_SIGNED: The charm will generate a self signed certificate.
    TLS_INTEGRATION: The charm will use the TLS integration relation.
    """

    SELF_SIGNED = 1
    TLS_INTEGRATION = 2


# TODO Move this class, it doesn't belong here.
class WorkloadBase(ABC):
    """Define an interface for the Machine and Container classes."""

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if a file exists in the workload."""
        pass

    @abstractmethod
    def pull(self, path: str) -> TextIO:
        """Read file from the workload."""
        pass

    @abstractmethod
    def push(self, path: str, source: str) -> None:
        """Write file to the workload."""
        pass

    @abstractmethod
    def make_dir(self, path: str) -> None:
        """Create directory in the workload."""
        pass

    @abstractmethod
    def remove_path(self, path: str, recursive: bool = False) -> None:
        """Remove file or directory from the workload."""
        pass

    @abstractmethod
    def send_signal(self, signal: int, process: str) -> None:
        """Send a signal to a process in the workload."""
        pass

    @abstractmethod
    def restart(self, process: str) -> None:
        """Restart the workload service."""

    @abstractmethod
    def stop(self, process: str) -> None:
        """Stop a service in the workload."""
        pass

    @abstractmethod
    def is_accessible(self) -> bool:
        """Return whether the workload is accessible.

        For a container, this would check if we can connect to pebble.
        """
        pass


class VaultCertsError(Exception):
    """Exception raised when a vault certificate is not found."""

    def __init__(self, message: str = "Could not retrieve vault certificates from local storage"):
        self.message = message
        super().__init__(self.message)


class File(Enum):
    """This enum determines which files are expected of the library to read."""

    CERT = auto()
    KEY = auto()
    CA = auto()
    AUTOUNSEAL_CA = auto()


class TLSManager(Object):
    """This class configures the certificates within Vault."""

    def __init__(
        self,
        charm: CharmBase,
        service_name: str,
        tls_directory_path: str,
        workload: WorkloadBase,
        common_name: str,
        sans_dns: FrozenSet[str] = frozenset(),
        sans_ip: FrozenSet[str] = frozenset(),
    ):
        """Create a new TLSManager object.

        Args:
            charm: CharmBase
            service_name: Name of the container in k8s and
                name of the process in machine.
            tls_directory_path: Path of the directory
                where certificates should be stored on the workload.
            workload: Either a Container or a Machine.
            common_name: The common name of the certificate
            sans_dns: Subject alternative names of the certificate
            sans_ip: Subject alternative IP addresses of the certificate
        """
        super().__init__(charm, "tls")
        self.charm = charm
        self.juju_facade = JujuFacade(charm)
        self.workload = workload
        self._service_name = service_name
        self.tls_directory_path = tls_directory_path
        self.common_name = common_name
        self.sans_dns = sans_dns
        self.sans_ip = sans_ip
        self.mode = self._get_mode()
        self.certificate_transfer = CertificateTransferProvides(charm, SEND_CA_CERT_RELATION_NAME)
        if self.mode == TLSMode.TLS_INTEGRATION:
            self.tls_access = TLSCertificatesRequiresV4(
                charm=charm,
                relationship_name=TLS_CERTIFICATE_ACCESS_RELATION_NAME,
                certificate_requests=self._get_certificate_requests(),
            )
            self.framework.observe(
                self.charm.on[TLS_CERTIFICATE_ACCESS_RELATION_NAME].relation_changed,
                self._configure_tls_integration,
            )
        elif self.mode == TLSMode.SELF_SIGNED:
            self.tls_access = None
            self.framework.observe(
                self.charm.on.config_changed, self._configure_self_signed_certificates
            )
            self.framework.observe(
                self.charm.on.update_status, self._configure_self_signed_certificates
            )
            self.framework.observe(
                self.charm.on[TLS_CERTIFICATE_ACCESS_RELATION_NAME].relation_broken,
                self._configure_self_signed_certificates,
            )
        self.framework.observe(
            self.charm.on[SEND_CA_CERT_RELATION_NAME].relation_joined,
            self._configure_ca_cert_relation,
        )
        self.framework.observe(
            self.charm.on.update_status,
            self._configure_ca_cert_relation,
        )

    def _configure_ca_cert_relation(self, event: EventBase):
        """Send the CA certificate to the relation."""
        self.send_ca_cert()

    def _get_certificate_requests(self) -> list[CertificateRequestAttributes]:
        if not self.common_name:
            return []
        return [
            CertificateRequestAttributes(
                common_name=self.common_name, sans_dns=self.sans_dns, sans_ip=self.sans_ip
            )
        ]

    def _get_mode(self) -> TLSMode:
        """Determine the TLS mode of the charm."""
        if self.juju_facade.relation_exists(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            return TLSMode.TLS_INTEGRATION
        return TLSMode.SELF_SIGNED

    def _configure_self_signed_certificates(self, _: EventBase) -> None:
        """Configure the charm with self signed certificates."""
        if not self.workload.is_accessible():
            logger.debug("Workload is not accessible")
            return
        if self.charm.unit.is_leader() and not self.ca_certificate_secret_exists():
            ca_private_key, ca_certificate = generate_vault_ca_certificate()
            self.juju_facade.set_app_secret_content(
                {"privatekey": ca_private_key, "certificate": ca_certificate},
                CA_CERTIFICATE_JUJU_SECRET_LABEL,
            )
            logger.info("Saved the Vault generated CA cert in juju secrets.")
        existing_ca_certificate = self.pull_tls_file_from_workload(File.CA)
        if existing_ca_certificate and existing_certificate_is_self_signed(
            ca_certificate=Certificate.from_string(existing_ca_certificate)
        ):
            workload_unit_cert = self.pull_tls_file_from_workload(File.CERT)
            if workload_unit_cert and self._unit_certificate_sans_match_current_request(workload_unit_cert):
                logger.debug("Found existing self signed certificate in workload with matching attributes.")
                return
        if not self.ca_certificate_secret_exists():
            logger.debug("No CA certificate found.")
            return
        try:
            ca_private_key, ca_certificate = self.juju_facade.get_secret_content_values(
                "privatekey",
                "certificate",
                label=CA_CERTIFICATE_JUJU_SECRET_LABEL,
            )
        except NoSuchSecretError:
            logger.error("Charm does not have permission to access the CA certificate secret.")
            return
        if not ca_certificate:
            logger.debug("No CA certificate found.")
            return
        if not ca_private_key:
            logger.debug("No CA private key found.")
            return
        unit_private_key, unit_certificate = generate_vault_unit_certificate(
            common_name=self.common_name,
            sans_dns=self.sans_dns,
            sans_ip=self.sans_ip,
            ca_certificate=ca_certificate,
            ca_private_key=ca_private_key,
        )
        self._push_tls_file_to_workload(File.KEY, unit_private_key)
        self._push_tls_file_to_workload(File.CERT, unit_certificate)
        self._push_tls_file_to_workload(File.CA, ca_certificate)
        logger.info(
            "Saved Vault generated CA and self signed certificate to %s.",
            self.juju_facade.unit_name,
        )
        self._restart_vault()

    def _configure_tls_integration(self, _: EventBase) -> None:
        """Configure the charm with the TLS integration relation.

        Retrieve assigned certificate and private key from the relation and save them to the workload.
        """
        if not self.workload.is_accessible():
            logger.debug("Workload is not accessible")
            return
        if not self.tls_access:
            logger.debug("No TLS access relation.")
            return
        certificate_requests = self._get_certificate_requests()
        if not certificate_requests:
            logger.debug("No certificate requests.")
            return
        assigned_certificate, private_key = self.tls_access.get_assigned_certificate(
            certificate_request=certificate_requests[0]
        )
        if not assigned_certificate:
            logger.debug("No certificate assigned.")
            return
        if not private_key:
            logger.debug("No private key assigned.")
            return
        restart = False
        if str(private_key) != self.pull_tls_file_from_workload(File.KEY):
            self._push_tls_file_to_workload(File.KEY, str(private_key))
            logger.info(
                "Private key from access relation saved for unit %s.",
                self.charm.unit.name,
            )
            restart = True
        if str(assigned_certificate.certificate) != self.pull_tls_file_from_workload(File.CERT):
            self._push_tls_file_to_workload(File.CERT, str(assigned_certificate.certificate))
            logger.info(
                "Certificate from access relation saved for unit %s.",
                self.charm.unit.name,
            )
            restart = True
        if self.pull_tls_file_from_workload(File.CA) != str(assigned_certificate.ca):
            self._push_tls_file_to_workload(File.CA, str(assigned_certificate.ca))
            restart = True
        if restart:
            self._restart_vault()

    def send_ca_cert(self):
        """Send the existing CA cert in the workload to all relations."""
        if ca := self.pull_tls_file_from_workload(File.CA):
            for relation in self.juju_facade.get_relations(SEND_CA_CERT_RELATION_NAME):
                self.certificate_transfer.set_certificate(
                    certificate="", ca=ca, chain=[], relation_id=relation.id
                )
                logger.info("Sent CA certificate to relation %s", relation.id)
        else:
            for relation in self.juju_facade.get_relations(SEND_CA_CERT_RELATION_NAME):
                self.certificate_transfer.remove_certificate(relation.id)
                logger.info("Removed CA cert from relation %s", relation.id)

    def get_tls_file_path_in_workload(self, file: File) -> str:
        """Return the requested file's location in the workload.

        Args:
            file: a File object that determines which file path to return
        Returns:
            the path of the file from the workload's perspective
        """
        return f"{self.tls_directory_path}/{file.name.lower()}.pem"

    def get_tls_file_path_in_charm(self, file: File) -> str:
        """Return the requested file's location in the charm (not in the workload).

        This path would typically be: /var/lib/juju/storage/certs/0/{file}.pem

        Args:
            file: a File object that determines which file path to return
        Returns:
            str: path
        Raises:
            VaultCertsError: If the CA certificate is not found
        """
        try:
            storage_location = self.juju_facade.get_storage_location("certs")
        except NoSuchStorageError:
            raise VaultCertsError()
        except TransientJujuError:
            raise
        return f"{storage_location}/{file.name.lower()}.pem"

    def tls_file_available_in_charm(self, file: File) -> bool:
        """Return whether the given file is available in the charm.

        Args:
            file: a File object that determines which file to check
        Returns:
            bool: True if file exists
        """
        try:
            file_path = self.get_tls_file_path_in_charm(file)
            return os.path.exists(file_path)
        except VaultCertsError:
            return False
        except TransientJujuError:
            raise

    def ca_certificate_is_saved(self) -> bool:
        """Return wether a CA cert and its private key are saved in the charm."""
        return self.ca_certificate_secret_exists() or self.tls_file_pushed_to_workload(File.CA)

    def _restart_vault(self) -> None:
        """Attempt to restart the Vault server."""
        try:
            self.workload.restart(self._service_name)
            logger.debug("Vault restarted")
        except Exception:
            logger.debug("Couldn't restart Vault. Proceeding normally.")

    def pull_tls_file_from_workload(self, file: File) -> str:
        """Get a file related to certs from the workload.

        Args:
            file: a File object that determines which file to read.

        Returns:
            str: The file content without whitespace
                Or an empty string if the file does not exist.
        """
        try:
            with self.workload.pull(
                self.get_tls_file_path_in_workload(file),
            ) as file_content:
                return file_content.read().strip()
        except (PathError, FileNotFoundError):
            return ""

    def ca_certificate_secret_exists(self) -> bool:
        """Return whether CA certificate is stored in secret."""
        return self.juju_facade.secret_exists_with_fields(
            fields=("privatekey", "certificate"),
            label=CA_CERTIFICATE_JUJU_SECRET_LABEL,
        )

    def _push_tls_file_to_workload(self, file: File, data: str) -> None:
        """Push one of the given file types to the workload.

        Args:
            file: a File object that determines which file to write.
            data: the data to write into that file.
        """
        self.workload.push(path=self.get_tls_file_path_in_workload(file), source=data)
        logger.debug("Pushed %s file to workload", file.name)

    def push_autounseal_ca_cert(self, ca_cert: str) -> None:
        """Push the CA certificate to the workload.

        Args:
            ca_cert: The CA certificate to push to the workload.
        """
        self.workload.push(self.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA), ca_cert)

    def _remove_tls_file_from_workload(self, file: File) -> None:
        """Remove the certificate files that are used for authentication.

        Args:
            file: a File object that determines which file to remove.
        """
        try:
            self.workload.remove_path(path=self.get_tls_file_path_in_workload(file))
        except PathError:
            pass
        logger.debug("Removed %s file from workload.", file.name)

    def tls_file_pushed_to_workload(self, file: File) -> bool:
        """Return whether tls file is pushed to the workload.

        Args:
            file: a File object that determines which file to check.

        Returns:
            bool: True if file exists.
        """
        return self.workload.exists(path=f"{self.tls_directory_path}/{file.name.lower()}.pem")

    def _unit_certificate_sans_match_current_request(self, unit_cert_content: str) -> bool:
        """Check if the unit certificate attributes match the current TLS manager configuration.

        Args:
            unit_cert_content: The PEM content of the unit certificate

        Returns:
            bool: True if certificate attributes match current configuration, False otherwise
        """
        try:
            unit_cert = Certificate.from_string(unit_cert_content)

            cert_sans_dns = set(unit_cert.sans_dns) if unit_cert.sans_dns else set()
            cert_sans_ip = set(unit_cert.sans_ip) if unit_cert.sans_ip else set()
            current_sans_dns = set(self.sans_dns) if self.sans_dns else set()
            current_sans_ip = set(self.sans_ip) if self.sans_ip else set()

            return (
                cert_sans_dns == current_sans_dns
                and cert_sans_ip == current_sans_ip
                and unit_cert.common_name == self.common_name
            )
        except Exception as e:
            logger.warning("Failed to parse unit certificate attributes: %s", e)
            return False


def generate_vault_ca_certificate() -> tuple[str, str]:
    """Generate Vault CA certificates valid for 50 years.

    Returns:
        Tuple[str, str]: CA Private key, CA certificate
    """
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        common_name=VAULT_CA_SUBJECT,
        validity=timedelta(days=365 * 50),
    )
    return str(ca_private_key), str(ca_certificate)


def generate_vault_unit_certificate(
    common_name: str,
    sans_ip: FrozenSet[str],
    sans_dns: FrozenSet[str],
    ca_certificate: str,
    ca_private_key: str,
) -> tuple[str, str]:
    """Generate Vault unit certificates valid for 50 years.

    Args:
        common_name: Common name of the certificate
        sans_ip: Subject alternative IP addresses of the certificate
        sans_dns: Subject alternative names of the certificate
        ca_certificate: CA certificate
        ca_private_key: CA private key

    Returns:
        Tuple[str, str]: Private key, Certificate
    """
    vault_private_key = generate_private_key()
    csr = generate_csr(
        private_key=vault_private_key,
        common_name=common_name,
        sans_ip=sans_ip,
        sans_dns=sans_dns,
    )
    vault_certificate = generate_certificate(
        ca=Certificate.from_string(ca_certificate),
        ca_private_key=PrivateKey.from_string(ca_private_key),
        csr=csr,
        validity=timedelta(days=365 * 50),
    )
    return str(vault_private_key), str(vault_certificate)


def existing_certificate_is_self_signed(ca_certificate: Certificate) -> bool:
    """Return whether the certificate is a self signed certificate generated by the Vault charm."""
    return ca_certificate.common_name == VAULT_CA_SUBJECT


class Naming:
    """Computes names for Vault features.

    This class is used to compute names for Vault features based on the charm's
    conventions, such as the key name, policy name, and approle name.  It
    provides a central place to manage them.
    """

    autounseal_approle_prefix: str = "charm-autounseal-"
    autounseal_key_prefix: str = ""
    autounseal_policy_prefix: str = "charm-autounseal-"
    backup_s3_key_prefix: str = "vault-backup-"
    kv_mount_prefix: str = "charm-"
    kv_secret_prefix: str = "vault-kv-"

    @classmethod
    def autounseal_key_name(cls, relation_id: int) -> str:
        """Return the key name for the relation."""
        return f"{cls.autounseal_key_prefix}{relation_id}"

    @classmethod
    def autounseal_policy_name(cls, relation_id: int) -> str:
        """Return the policy name for the relation."""
        return f"{cls.autounseal_policy_prefix}{relation_id}"

    @classmethod
    def autounseal_approle_name(cls, relation_id: int) -> str:
        """Return the approle name for the relation."""
        return f"{cls.autounseal_approle_prefix}{relation_id}"

    @classmethod
    def backup_s3_key_name(cls, model_name: str) -> str:
        """Return the key name for the S3 backend."""
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return f"{cls.backup_s3_key_prefix}{model_name}-{timestamp}"

    @classmethod
    def kv_secret_label(cls, unit_name: str) -> str:
        """Return the secret label for the KV backend."""
        unit_name_dash = unit_name.replace("/", "-")
        return f"{cls.kv_secret_prefix}{unit_name_dash}"

    @classmethod
    def kv_mount_path(cls, app_name: str, mount_suffix: str) -> str:
        """Return the mount path for the KV backend."""
        return f"{cls.kv_mount_prefix}{app_name}-{mount_suffix}"

    @classmethod
    def kv_policy_name(cls, mount_path: str, unit_name: str) -> str:
        """Return the policy name for the KV backend."""
        unit_name_dash = unit_name.replace("/", "-")
        return f"{mount_path}-{unit_name_dash}"

    @classmethod
    def kv_role_name(cls, mount_path: str, unit_name: str) -> str:
        """Return the role name for the KV backend."""
        unit_name_dash = unit_name.replace("/", "-")
        return f"{mount_path}-{unit_name_dash}"


class AutounsealProviderManager:
    """Encapsulates the auto-unseal functionality.

    This class provides the business logic for auto-unseal functionality in
    Vault charms. It is opinionated, and aims to make the interface to enabling
    and managing the feature as simple as possible. Flexibility is sacrificed
    for simplicity.
    """

    def __init__(
        self,
        charm: CharmBase,
        client: VaultClient,
        provides: VaultAutounsealProvides,
        ca_cert: str,
        mount_path: str,
    ):
        self._juju_facade = JujuFacade(charm)
        self._model = charm.model
        self._client = client
        self._provides = provides
        self._mount_path = mount_path
        self._ca_cert = ca_cert

    @property
    def mount_path(self) -> str:
        """Return the mount path for the transit backend."""
        return self._mount_path

    def clean_up_credentials(self) -> None:
        """Clean up roles and policies that are no longer needed by autounseal.

        This method will remove any roles and policies that are no longer
        used by any of the existing relations. It will also detect any orphaned
        keys (keys that are not associated with any relation) and log a warning.
        """
        self._clean_up_roles()
        self._clean_up_policies()
        self._detect_and_allow_deletion_of_orphaned_keys()

    def _detect_and_allow_deletion_of_orphaned_keys(self) -> None:
        """Detect and allow deletion of autounseal keys that are no longer associated with a Juju autounseal relation.

        The keys themselves are not deleted. This is to prevent an
        unrecoverable state if a relation is removed by mistake, or before
        migrating the data to a different seal type.

        The keys are marked as `allow_deletion` in vault. This allows the user
        to manually delete the keys using the Vault CLI if they are sure the
        keys are no longer needed.

        A warning is logged so that the Juju operator is aware of the orphaned
        keys and can act accordingly.
        """
        existing_keys = self._get_existing_keys()
        relation_key_names = [
            Naming.autounseal_key_name(relation.id)
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        orphaned_keys = [key for key in existing_keys if key not in relation_key_names]
        if not orphaned_keys:
            return
        logger.warning(
            "Orphaned autounseal keys were detected: %s. If you are sure these are no longer needed, you may manually delete them using the vault CLI to suppress this message. To delete a key, use the command `vault delete %s/keys/<key_name>`.",
            orphaned_keys,
            self.mount_path,
        )
        for key_name in orphaned_keys:
            deletion_allowed = self._is_deletion_allowed(key_name)
            if not deletion_allowed:
                self._allow_key_deletion(key_name)

    def _allow_key_deletion(self, key_name: str) -> None:
        self._client.write(f"{self.mount_path}/keys/{key_name}/config", {"deletion_allowed": True})
        logger.info("Key marked as `deletion_allowed`: %s", key_name)

    def _is_deletion_allowed(self, key_name: str) -> bool:
        data = self._client.read(f"{self.mount_path}/keys/{key_name}")
        return data["deletion_allowed"]

    def _clean_up_roles(self) -> None:
        """Delete roles that are no longer associated with an autounseal Juju relation."""
        existing_roles = self._get_existing_roles()
        relation_role_names = [
            Naming.autounseal_approle_name(relation.id)
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        for role in existing_roles:
            if role not in relation_role_names:
                self._client.delete_role(role)
                logger.info("Removed unused role: %s", role)

    def _clean_up_policies(self) -> None:
        """Delete policies that are no longer associated with an autounseal Juju relation."""
        existing_policies = self._get_existing_policies()
        relation_policy_names = [
            Naming.autounseal_policy_name(relation.id)
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        for policy in existing_policies:
            if policy not in relation_policy_names:
                self._client.delete_policy(policy)
                logger.info("Removed unused policy: %s", policy)

    def _create_key(self, key_name: str) -> None:
        response = self._client.create_transit_key(mount_point=self.mount_path, key_name=key_name)
        logger.debug("Created a new autounseal key: %s", response)

    def create_credentials(self, relation: Relation, vault_address: str) -> tuple[str, str, str]:
        """Create auto-unseal credentials for the given relation.

        Args:
            relation: The relation to create the credentials for.
            vault_address: The address where this relation can reach the Vault.

        Returns:
            A tuple containing the key name, role ID, and approle secret ID.
        """
        key_name = Naming.autounseal_key_name(relation.id)
        policy_name = Naming.autounseal_policy_name(relation.id)
        approle_name = Naming.autounseal_approle_name(relation.id)
        self._create_key(key_name)
        policy_content = AUTOUNSEAL_POLICY.format(mount=self.mount_path, key_name=key_name)
        self._client.create_or_update_policy(
            policy_name,
            policy_content,
        )
        role_id = self._client.create_or_update_approle(
            approle_name,
            policies=[policy_name],
            token_period="60s",
        )
        secret_id = self._client.generate_role_secret_id(approle_name)
        self._provides.set_autounseal_data(
            relation,
            vault_address,
            self.mount_path,
            key_name,
            role_id,
            secret_id,
            self._ca_cert,
        )
        return key_name, role_id, secret_id

    def _get_existing_keys(self) -> list[str]:
        return self._client.list(f"{self.mount_path}/keys")

    def _get_existing_roles(self) -> list[str]:
        output = self._client.list("auth/approle/role")
        return [role for role in output if role.startswith(Naming.autounseal_approle_prefix)]

    def _get_existing_policies(self) -> list[str]:
        output = self._client.list("sys/policy")
        return [policy for policy in output if policy.startswith(Naming.autounseal_policy_prefix)]


@dataclass
class AutounsealConfigurationDetails:
    """Credentials required for configuring auto-unseal on Vault."""

    address: str
    mount_path: str
    key_name: str
    token: str
    ca_cert_path: str


class AutounsealRequirerManager:
    """Encapsulates the auto-unseal functionality from the Requirer Perspective.

    In other words, this manages the feature from the perspective of the Vault
    being auto-unsealed.
    """

    AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"

    def __init__(
        self,
        charm: CharmBase,
        requires: VaultAutounsealRequires,
    ):
        self._juju_facade = JujuFacade(charm)
        self._requires = requires

    def get_provider_vault_token(
        self, autounseal_details: AutounsealDetails, ca_cert_path: str
    ) -> str:
        """Retrieve the auto-unseal Vault token, or generate a new one if required.

        Retrieves the last used token from Juju secrets, and validates that it
        is still valid. If the token is not valid, a new token is generated and
        stored in the Juju secret. A valid token is returned.

        Args:
            autounseal_details: The autounseal configuration details.
            ca_cert_path: The path to the CA certificate to validate the provider Vault.

        Returns:
            A periodic Vault token that can be used for auto-unseal.

        """
        external_vault = VaultClient(url=autounseal_details.address, ca_cert_path=ca_cert_path)
        try:
            existing_token = self._juju_facade.get_secret_content_values(
                "token", label=self.AUTOUNSEAL_TOKEN_SECRET_LABEL
            )[0]
        except FacadeError:
            existing_token = None
        # If we don't already have a token, or if the existing token is invalid,
        # authenticate with the AppRole details to generate a new token.
        if not existing_token or not external_vault.authenticate(Token(existing_token)):
            external_vault.authenticate(
                AppRole(autounseal_details.role_id, autounseal_details.secret_id)
            )
            # NOTE: This is a little hacky. If the token expires, every unit
            # will generate a new token, until the leader unit generates a new
            # valid token and sets it in the Juju secret.
            if self._juju_facade.is_leader:
                self._juju_facade.set_app_secret_content(
                    {"token": external_vault.token},
                    label=self.AUTOUNSEAL_TOKEN_SECRET_LABEL,
                )
        return external_vault.token


class PKIManager:
    """Encapsulates the business logic for managing PKI certificates in Vault from a Charm."""

    def __init__(
        self,
        charm: CharmBase,
        vault_client: VaultClient,
        certificate_request_attributes: CertificateRequestAttributes,
        mount_point: str,
        role_name: str,
        vault_pki: TLSCertificatesProvidesV4,
        tls_certificates_pki: TLSCertificatesRequiresV4,
    ):
        """Create a new PKIManager object.

        Args:
            charm: The charm this manager is associated with
            vault_client: The Vault client object
            certificate_request_attributes: The certificate request attributes
                that were used when requesting an intermediate certificate from
                the tls_certificates_pki relation provider.
            mount_point: The mount point in Vault for the PKI backend
            role_name: The role name for the PKI backend
            vault_pki: The vault_pki provider relation helper library
            tls_certificates_pki: The tls_certificates_pki requirer relation helper library
        """
        self._vault_client = vault_client
        self._juju_facade = JujuFacade(charm)
        self._mount_point = mount_point
        self._role_name = role_name
        self._vault_pki = vault_pki
        self._tls_certificates_pki = tls_certificates_pki
        self._certificate_request_attributes = certificate_request_attributes

    def _get_pki_intermediate_ca_from_relation(
        self,
    ) -> tuple[ProviderCertificate | None, PrivateKey | None]:
        """Get the intermediate CA certificate and private key from the relation data.

        This is the CA certificate that the provider charm has issued to Vault.
        """
        provider_certificate, private_key = self._tls_certificates_pki.get_assigned_certificate(
            certificate_request=self._certificate_request_attributes
        )
        if not provider_certificate:
            logger.debug("No intermediate CA certificate available")
        if not private_key:
            logger.debug("No private key available")
        return provider_certificate, private_key

    def _get_vault_service_ca_certificate(self) -> Certificate | None:
        """Get the current CA certificate from the Vault service."""
        try:
            intermediate_ca_cert = self._vault_client.get_intermediate_ca(mount=self._mount_point)
            if not intermediate_ca_cert:
                return None
            return Certificate.from_string(intermediate_ca_cert)
        except (VaultClientError, TLSCertificatesError) as e:
            logger.error("Failed to get current CA certificate: %s", e)
            return None

    def _intermediate_ca_exceeds_role_ttl(self, intermediate_ca_certificate: Certificate) -> bool:
        """Check if the intermediate CA's remaining validity exceeds the role's max TTL.

        Vault PKI enforces that issued certificates cannot outlast their signing CA.
        This method ensures that the intermediate CA's remaining validity period
        is longer than the maximum TTL allowed for certificates issued by this role.
        """
        current_ttl = self._vault_client.get_role_max_ttl(
            role=self._role_name, mount=self._mount_point
        )
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

    def configure(self):
        """Enable the PKI backend and update the PKI role in Vault.

        This method retrieves the intermediate certificate from the relation
        and configures the PKI role in Vault if they have changed (or haven't
        yet been configured). It will also revoke all existing certificates if
        the provider has issued a new CA certificate, and ensure all future
        certificates are issued by the new CA certificate.

        Additionally, this method ensures that the intermediate CA certificate
        is renewed if necessary.
        """
        if not self._juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-pki certificate requests")
            return
        if not self._juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("No PKI relation exists: `%s`", TLS_CERTIFICATES_PKI_RELATION_NAME)
            return
        self._vault_client.enable_secrets_engine(SecretsBackend.PKI, self._mount_point)
        logger.info("Enabled PKI secrets engine at %s", self._mount_point)

        certificate_from_provider, private_key = self._get_pki_intermediate_ca_from_relation()
        if not certificate_from_provider or not private_key:
            return
        vault_service_ca_certificate = self._get_vault_service_ca_certificate()
        if (
            vault_service_ca_certificate
            and vault_service_ca_certificate == certificate_from_provider.certificate
        ):
            if not self._intermediate_ca_exceeds_role_ttl(vault_service_ca_certificate):
                self._tls_certificates_pki.renew_certificate(
                    certificate_from_provider,
                )
                logger.debug("Renewing CA certificate")
                return
            logger.debug("CA certificate already set in the PKI secrets engine")
            return
        self._vault_pki.revoke_all_certificates()
        self._vault_client.import_ca_certificate_and_key(
            certificate=str(certificate_from_provider.certificate),
            private_key=str(private_key),
            mount=self._mount_point,
        )
        issued_certificates_validity = PKIManager.calculate_pki_certificates_ttl(
            certificate_from_provider.certificate
        )
        if not self._vault_client.is_common_name_allowed_in_pki_role(
            role=self._role_name,
            mount=self._mount_point,
            common_name=self._certificate_request_attributes.common_name,
        ) or issued_certificates_validity != self._vault_client.get_role_max_ttl(
            role=self._role_name, mount=self._mount_point
        ):
            self._vault_client.create_or_update_pki_charm_role(
                allowed_domains=self._certificate_request_attributes.common_name,
                mount=self._mount_point,
                role=self._role_name,
                max_ttl=f"{issued_certificates_validity}s",
            )
        self.make_latest_pki_issuer_default()

    def make_latest_pki_issuer_default(self):
        """Make the latest PKI issuer the default issuer.

        This ensures that the latest issuer we have created is used for signing
        certificates.
        """
        try:
            first_issuer = self._vault_client.list_pki_issuers(mount=self._mount_point)[0]
        except (VaultClientError, IndexError) as e:
            logger.error("Failed to get the first issuer: %s", e)
            return
        try:
            issuers_config = self._vault_client.read(path=f"{self._mount_point}/config/issuers")
            if issuers_config and not issuers_config["default_follows_latest_issuer"]:
                logger.debug("Updating issuers config")
                self._vault_client.write(
                    path=f"{self._mount_point}/config/issuers",
                    data={
                        "default_follows_latest_issuer": True,
                        "default": first_issuer,
                    },
                )
        except (TypeError, KeyError):
            logger.error("Issuers config is not yet created")

    def sync(self):
        """Sync the state of the PKI backend with the TLS certificates relations.

        Issues certificates for all outstanding requests.
        """
        if not self._juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        if not self._juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("TLS Certificates PKI relation not created")
            return
        outstanding_pki_requests = self._vault_pki.get_outstanding_certificate_requests()
        for pki_request in outstanding_pki_requests:
            self._generate_pki_certificate_for_requirer(
                requirer_csr=pki_request,
            )

    def _generate_pki_certificate_for_requirer(self, requirer_csr: RequirerCertificateRequest):
        if not self._vault_client.is_pki_role_created(
            role=self._role_name, mount=self._mount_point
        ):
            logger.debug("PKI role not created")
            return
        provider_certificate, _ = self._get_pki_intermediate_ca_from_relation()
        if not provider_certificate:
            return
        allowed_cert_validity = PKIManager.calculate_pki_certificates_ttl(
            provider_certificate.certificate
        )
        certificate = self._vault_client.sign_pki_certificate_signing_request(
            mount=self._mount_point,
            role=self._role_name,
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
            chain=[Certificate.from_string(certificate.certificate)]
            + [Certificate.from_string(cert) for cert in certificate.chain],
        )
        self._vault_pki.set_relation_certificate(
            provider_certificate=provider_certificate,
        )

    @staticmethod
    def calculate_pki_certificates_ttl(certificate: Certificate) -> int:
        """Calculate the maximum allowed validity of certificates issued by PKI.

        The current implementation returns half the validity of the CA certificate.
        """
        if not certificate.expiry_time or not certificate.validity_start_time:
            raise ValueError("Invalid CA certificate with no expiry time or validity start time")
        ca_validity_time = certificate.expiry_time - certificate.validity_start_time
        ca_validity_seconds = ca_validity_time.total_seconds()
        return int(ca_validity_seconds / 2)


class KVManager:
    """Encapsulates the business logic for managing KV credentials for requirer Charms."""

    def __init__(
        self,
        charm: CharmBase,
        vault_client: VaultClient,
        vault_kv: VaultKvProvides,
        ca_cert: str,
    ):
        self._vault_client = vault_client
        self._juju_facade = JujuFacade(charm)
        self._vault_kv = vault_kv
        self._ca_cert = ca_cert

    def generate_credentials_for_requirer(
        self,
        relation: Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnets: list[str],
        nonce: str,
        vault_url: str,
    ):
        """Generate KV credentials for the requirer, and store the credentials in the relation.

        This method ensures that the approle and policy are created or updated,
        and that the approle secret ID is generated and stored in a Juju secret.

        The Juju secret ID is then passed to the requirer, along with other
        necessary information to access the KV backend.

        Args:
            relation: The relation of the requirer
            app_name: The name of the requirer application
            unit_name: The name of the requirer unit for this relation
            mount_suffix: The suffix to append to the mount path, as provided by the requirer
            egress_subnets: The egress subnets of the requirer
            nonce: The nonce provided by the requirer
            vault_url: The URL of the Vault server that the requirer can access
                over this relation.
        """
        if not self._juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        mount = Naming.kv_mount_path(app_name, mount_suffix)
        self._vault_client.enable_secrets_engine(SecretsBackend.KV_V2, mount)
        secret_id = self._ensure_unit_credentials(
            relation=relation,
            unit_name=unit_name,
            mount=mount,
            nonce=nonce,
            egress_subnets=egress_subnets,
        )
        self._vault_kv.set_kv_data(
            relation=relation,
            mount=mount,
            ca_certificate=self._ca_cert,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id=secret_id,
        )
        self._remove_stale_nonce(relation=relation, nonce=nonce)

    def _remove_stale_nonce(self, relation: Relation, nonce: str) -> None:
        """Remove stale nonce.

        If the nonce is not present in the credentials, it is stale and should be removed.

        Args:
            relation: the reltaion from which to check the credentials for the nonce
            nonce: the one to remove if stale
        """
        credential_nonces = self._vault_kv.get_credentials(relation).keys()
        if nonce not in set(credential_nonces):
            self._vault_kv.remove_unit_credentials(relation, nonce=nonce)

    def _ensure_unit_credentials(
        self,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnets: list[str],
    ) -> str:
        """Ensure a unit has credentials to access the vault-kv mount.

        If the credentials are already configured for the provided egress
        subnets, the existing Juju secret ID which contains the approle secret
        ID is returned.

        Otherwise, the necessary Vault policy and approle are created or
        updated as necessary.  A Vault secret ID is then generated for the
        approle and stored in a Juju secret. The secret is granted to the
        associate relation, and the ID of the Juju secret is returned.

        Returns:
            The ID of the Juju secret containing the approle secret ID.
        """
        policy_name = Naming.kv_policy_name(mount, unit_name)
        role_name = Naming.kv_role_name(mount, unit_name)

        juju_secret_label = Naming.kv_secret_label(unit_name=unit_name)
        current_credentials = self._vault_kv.get_credentials(relation)
        credentials_juju_secret_id = current_credentials.get(nonce, None)

        if self._is_vault_kv_role_configured(
            label=juju_secret_label,
            egress_subnets=egress_subnets,
            role_name=role_name,
            credentials_juju_secret_id=credentials_juju_secret_id,
        ):
            logger.info("Vault KV role already configured for the provided egress subnets")
            return credentials_juju_secret_id
        self._vault_client.create_or_update_policy(policy_name, KV_POLICY.format(mount=mount))
        role_id = self._vault_client.create_or_update_approle(
            role_name,
            policies=[policy_name],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        role_secret_id = self._vault_client.generate_role_secret_id(role_name, egress_subnets)
        secret = self._juju_facade.set_app_secret_content(
            content={"role-id": role_id, "role-secret-id": role_secret_id},
            label=juju_secret_label,
        )
        self._juju_facade.grant_secret(relation, secret=secret)
        if not secret.id:
            raise ValueError(
                f"Unexpected error, just created secret {juju_secret_label!r} has no id"
            )
        return secret.id

    def _is_vault_kv_role_configured(
        self,
        label: str,
        egress_subnets: list[str],
        role_name: str,
        credentials_juju_secret_id: str,
    ) -> bool:
        """Check if the Vault role is already configured for the provided egress subnets.

        Args:
            label: The label of the secret
            egress_subnets: The egress subnets provided by the requirer.
            role_name: The role name associated with KV for this unit.
            credentials_juju_secret_id: The juju secret id.

        Returns:
            True if the role is already configured with the provided egress
        subnets, False otherwise.
        """
        try:
            role_secret_id = self._juju_facade.get_latest_secret_content(
                label=label,
                id=credentials_juju_secret_id,
            ).get("role-secret-id")
        except NoSuchSecretError:
            return False
        if not role_secret_id:
            return False
        role_data = self._vault_client.read_role_secret(role_name, role_secret_id)
        if egress_subnets == role_data["cidr_list"]:
            return True
        return False

    @staticmethod
    def remove_unit_credentials(juju_facade: JujuFacade, unit_name: str) -> None:
        """Remove any KV credentials associated with the given unit.

        Args:
            juju_facade: The JujuFacade object to use for removing the secret
            unit_name: The name of the unit for which to remove the secret
        """
        juju_facade.remove_secret(Naming.kv_secret_label(unit_name=unit_name))


class BackupManager:
    """Encapsulates the business logic for managing backups in Vault from a Charm.

    This class provides the business logic for creating, listing, and restoring
    backups of the Vault data.
    """

    REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]

    def __init__(
        self,
        charm: CharmBase,
        s3_requirer: S3Requirer,
        relation_name: str,
    ):
        self._charm = charm
        self._juju_facade = JujuFacade(charm)
        self._s3_requirer = s3_requirer
        self._relation_name = relation_name

    def create_backup(self, vault_client: VaultClient) -> str:
        """Create a backup of the Vault data.

        Stores the backup in the S3 bucket provided by the S3 relation.

        Returns:
            The S3 key of the backup.
        """
        self._validate_s3_prerequisites()

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error as e:
            logger.error("Failed to create S3 session. %s", e)
            raise ManagerError("Failed to create S3 session")

        if not (s3.create_bucket(bucket_name=s3_parameters["bucket"])):
            raise ManagerError("Failed to create S3 bucket")
        backup_key = Naming.backup_s3_key_name(self._charm.model.name)

        response = vault_client.create_snapshot()
        content_uploaded = s3.upload_content(
            content=response.raw,  # type: ignore[reportArgumentType]
            bucket_name=s3_parameters["bucket"],
            key=backup_key,
        )
        if not content_uploaded:
            raise ManagerError("Failed to upload backup to S3 bucket")
        logger.info("Backup uploaded to S3 bucket %s", s3_parameters["bucket"])
        return backup_key

    def list_backups(self) -> list[str]:
        """List all the backups available in the S3 bucket.

        Backups are identified by the key prefix from
        ``Naming.backup_s3_key_prefix``.

        Returns:
            A list of backup keys with the prefix.
        """
        self._validate_s3_prerequisites()

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error:
            raise ManagerError("Failed to create S3 session")

        try:
            backup_ids = s3.get_object_key_list(
                bucket_name=s3_parameters["bucket"], prefix=Naming.backup_s3_key_prefix
            )
        except S3Error as e:
            raise ManagerError(f"Failed to list backups in S3 bucket: {e}")
        return backup_ids

    def restore_backup(self, vault_client: VaultClient, backup_key: str) -> None:
        """Restore the Vault data from the backup using the ``vault_client`` provided.

        Args:
            vault_client: The Vault client to use for restoring the snapshot
            backup_key: The S3 key of the backup to restore
        """
        self._validate_s3_prerequisites()

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error:
            raise ManagerError("Failed to create S3 session")

        try:
            snapshot = s3.get_content(
                bucket_name=s3_parameters["bucket"],
                object_key=backup_key,
            )
        except S3Error as e:
            raise ManagerError(f"Failed to retrieve snapshot from S3: {e}")
        if not snapshot:
            raise ManagerError("Snapshot not found in S3 bucket")

        try:
            vault_client.restore_snapshot(snapshot=snapshot)
        except VaultClientError as e:
            raise ManagerError(f"Failed to restore snapshot: {e}")

    def _validate_s3_prerequisites(self) -> str | None:
        """Validate the S3 pre-requisites are met.

        Raises:
            ManagerError: If any of the pre-requisites are not met.
        """
        if not self._juju_facade.is_leader:
            raise ManagerError("Only leader unit can perform backup operations")
        if not self._juju_facade.relation_exists(self._relation_name):
            raise ManagerError("S3 relation not created")
        if missing_parameters := self._get_missing_s3_parameters():
            raise ManagerError("S3 parameters missing ({})".format(", ".join(missing_parameters)))

    def _get_missing_s3_parameters(self) -> list[str]:
        """Return the list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self._s3_requirer.get_s3_connection_info()
        return [param for param in self.REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _get_s3_parameters(self) -> dict[str, str]:
        """Retrieve S3 parameters from the S3 integrator relation.

        Removes leading and trailing whitespaces from the parameters.

        Returns:
            Dict[str, str]: Dictionary of the S3 parameters.
        """
        s3_parameters = self._s3_requirer.get_s3_connection_info()
        for key, value in s3_parameters.items():
            if isinstance(value, str):
                s3_parameters[key] = value.strip()
        return s3_parameters


class RaftManager:
    """Encapsulates the business logic for managing the bootstrap of a Vault cluster in Raft mode."""

    def __init__(
        self,
        charm: CharmBase,
        workload: WorkloadBase,
        service_name: str,
        storage_path: str,
    ):
        self._juju_facade = JujuFacade(charm)
        self._workload = workload
        self._service_name = service_name
        self._storage_path = storage_path

    def bootstrap(self, node_id: str, address: str) -> None:
        """Bootstrap a Vault cluster in Raft mode.

        This method will bootstrap a Vault cluster for a single node, by
        identifying itself as the sole node in the cluster. Additional units
        may then be added once the cluster is available.
        """
        if not self._juju_facade.is_leader:
            logger.debug("Only leader unit can bootstrap a Vault cluster")
            raise ManagerError("Only the leader unit can bootstrap a Vault cluster")
        if not self._juju_facade.planned_units_for_app == 1:
            raise ManagerError("Bootstrapping a Vault cluster requires exactly one unit")

        self._workload.stop(self._service_name)
        self._push_peers_json(node_id, address)
        self._workload.restart(self._service_name)

        logger.info("Vault cluster bootstrapped in Raft mode")

    def _push_peers_json(self, node_id: str, address: str) -> None:
        """Create the peers.json file for the Vault cluster.

        This method will create the peers.json file for the Vault cluster based
        on the ``node_id`` and ``address`` provided.
        """
        pass
        self._workload.push(
            f"{self._storage_path}/raft/peers.json", self._get_peers_json(node_id, address)
        )

    def _get_peers_json(self, node_id: str, address: str) -> str:
        """Return the peers.json file content for bootstrapping raft.

        This method will return the content of the peers.json file based on the
        ``node_id`` and ``address`` provided.
        """
        return json.dumps([{"id": node_id, "address": address}])
