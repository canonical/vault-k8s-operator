"""Library for managing Vault Charm features.

This library encapsulates the business logic for managing the Vault service and
its associated integrations within the context of our charms.
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto
from typing import FrozenSet, TextIO

from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    PrivateKey,
    TLSCertificatesRequiresV4,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from charms.vault_k8s.v0.juju_facade import (
    JujuFacade,
    NoSuchSecretError,
    NoSuchStorageError,
    SecretRemovedError,
    TransientJujuError,
)
from charms.vault_k8s.v0.vault_autounseal import (
    AutounsealDetails,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    SecretsBackend,
    Token,
    VaultClient,
)
from ops import CharmBase, EventBase, Object, Relation
from ops.pebble import PathError

# The unique Charmhub library identifier, never change it
LIBID = "4a8652e06ecb4eb28c5fdbf220d126bb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


SEND_CA_CERT_RELATION_NAME = "send-ca-cert"
TLS_CERTIFICATE_ACCESS_RELATION_NAME = "tls-certificates-access"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "self-signed-vault-ca-certificate"

VAULT_CA_SUBJECT = "Vault self signed CA"
AUTOUNSEAL_POLICY = """path "{mount}/encrypt/{key_name}" {{
    capabilities = ["update"]
}}

path "{mount}/decrypt/{key_name}" {{
    capabilities = ["update"]
}}
"""


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_managers"

    def process(self, msg, kwargs):
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})


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


class VaultTLSManager(Object):
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
        """Create a new VaultTLSManager object.

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
            logger.debug("Found existing self signed certificate in workload.")
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


class VaultAutounsealNaming:
    """Computes the auto-unseal related values for a relation.

    This class is used to compute the static details for a vault-autounseal
    relation, such as the key name, policy name, and approle name. These values
    are all based on the relation ID.

    This class provides a central place to manage the naming conventions for
    the auto-unseal functionality.
    """

    key_prefix: str = ""
    policy_prefix: str = "charm-autounseal-"
    approle_prefix: str = "charm-autounseal-"

    @classmethod
    def key_name(cls, relation_id) -> str:
        """Return the key name for the relation."""
        return f"{cls.key_prefix}{relation_id}"

    @classmethod
    def policy_name(cls, relation_id) -> str:
        """Return the policy name for the relation."""
        return f"{cls.policy_prefix}{relation_id}"

    @classmethod
    def approle_name(cls, relation_id) -> str:
        """Return the approle name for the relation."""
        return f"{cls.approle_prefix}{relation_id}"


class VaultAutounsealProviderManager:
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
        vault_port: int,
        mount_path: str = "charm-autounseal",
    ):
        self._juju_facade = JujuFacade(charm)
        self._model = charm.model
        self._client = client
        self._provides = provides
        self._mount_path = mount_path
        self._ca_cert = ca_cert
        self._port = vault_port

    def get_address(self, relation: Relation) -> str:
        """Fetch the address from the relation and return it."""
        return f"https://{self._juju_facade.get_ingress_address(relation)}:{self._port}"

    @property
    def mount_path(self) -> str:
        """Return the mount path for the transit backend."""
        return self._mount_path

    def sync(self) -> None:
        """Ensure that all auto-unseal requests are fulfilled and clean up unused credentials.

        This looks for any outstanding requests for auto-unseal that may have
        been missed. If there are any, it generates the credentials and sets
        them in the relation databag.

        It also cleans up any credentials that are no longer used by any of the
        relations, and logs a warning about orphaned keys. It will not remove
        any keys, to prevent loss of data.
        """
        if not self._juju_facade.is_leader:
            return
        outstanding_requests = self._provides.get_outstanding_requests()
        if outstanding_requests:
            self._client.enable_secrets_engine(SecretsBackend.TRANSIT, self._mount_path)
        for relation in outstanding_requests:
            self.create_credentials(relation)

        self._clean_up_credentials()

    def _clean_up_credentials(self) -> None:
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
            VaultAutounsealNaming.key_name(relation.id)
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
            VaultAutounsealNaming.approle_name(relation.id)
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
            VaultAutounsealNaming.policy_name(relation.id)
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        for policy in existing_policies:
            if policy not in relation_policy_names:
                self._client.delete_policy(policy)
                logger.info("Removed unused policy: %s", policy)

    def _create_key(self, key_name: str) -> None:
        response = self._client.create_transit_key(mount_point=self.mount_path, key_name=key_name)
        logger.debug("Created a new autounseal key: %s", response)

    def create_credentials(self, relation: Relation) -> tuple[str, str, str]:
        """Create auto-unseal credentials for the given relation.

        Args:
            relation: The relation to create the credentials for.

        Returns:
            A tuple containing the key name, role ID, and approle secret ID.
        """
        key_name = VaultAutounsealNaming.key_name(relation.id)
        policy_name = VaultAutounsealNaming.policy_name(relation.id)
        approle_name = VaultAutounsealNaming.approle_name(relation.id)
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
            self.get_address(relation),
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
        return [role for role in output if role.startswith(VaultAutounsealNaming.approle_prefix)]

    def _get_existing_policies(self) -> list[str]:
        output = self._client.list("sys/policy")
        return [
            policy for policy in output if policy.startswith(VaultAutounsealNaming.policy_prefix)
        ]


@dataclass
class AutounsealConfigurationDetails:
    """Credentials required for configuring auto-unseal on Vault."""

    address: str
    mount_path: str
    key_name: str
    token: str
    ca_cert_path: str


class VaultAutounsealRequirerManager:
    """Encapsulates the auto-unseal functionality from the Requirer Perspective.

    In other words, this manages the feature from the perspective of the Vault
    being auto-unsealed.
    """

    AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"

    def __init__(
        self,
        charm: CharmBase,
        tls_manager: VaultTLSManager,
        requires: VaultAutounsealRequires,
    ):
        self._juju_facade = JujuFacade(charm)
        self._tls_manager = tls_manager
        self._requires = requires

    def get_vault_configuration_details(self) -> AutounsealConfigurationDetails | None:
        """Return the necessary configuration details to properly configure auto-unseal."""
        autounseal_details = self._requires.get_details()
        if not autounseal_details:
            return None
        self._tls_manager.push_autounseal_ca_cert(autounseal_details.ca_certificate)
        ca_cert_path = self._tls_manager.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA)
        return AutounsealConfigurationDetails(
            autounseal_details.address,
            autounseal_details.mount_path,
            autounseal_details.key_name,
            self._get_autounseal_vault_token(autounseal_details),
            ca_cert_path,
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
        external_vault = VaultClient(
            url=autounseal_details.address,
            ca_cert_path=self._tls_manager.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA),
        )
        try:
            existing_token = self._juju_facade.get_secret_content_values(
                "token", label=self.AUTOUNSEAL_TOKEN_SECRET_LABEL
            )[0]
        except SecretRemovedError:
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
