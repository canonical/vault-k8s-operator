# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""This file includes methods to manage TLS certificates within the Vault charms."""

import logging
import os
import socket
from abc import ABC, abstractmethod
from enum import Enum, auto
from signal import SIGHUP
from typing import List, Optional, TextIO, Tuple

from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tls_certificates_interface.v3.tls_certificates import (
    TLSCertificatesRequiresV3,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import EventBase, Object, RelationBrokenEvent, SecretNotFoundError
from ops.charm import CharmBase
from ops.pebble import PathError

# The unique Charmhub library identifier, never change it
LIBID = "61b41a053d9847ce8a14eb02197d12cb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 9


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_tls"

    def process(self, msg, kwargs):
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})

SEND_CA_CERT_RELATION_NAME = "send-ca-cert"
TLS_CERTIFICATE_ACCESS_RELATION_NAME = "tls-certificates-access"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "self-signed-vault-ca-certificate"

VAULT_CA_SUBJECT = "Vault self signed CA"


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
    CSR = auto()
    AUTOUNSEAL_CA = auto()


class VaultTLSManager(Object):
    """This class configures the certificates within Vault."""

    def __init__(
        self,
        charm: CharmBase,
        service_name: str,
        tls_directory_path: str,
        workload: WorkloadBase,
    ):
        """Create a new VaultTLSManager object.

        Args:
            charm: CharmBase
            service_name: Name of the container in k8s and
                name of the process in machine.
            tls_directory_path: Path of the directory
                where certificates should be stored on the workload.
            workload: Either a Container or a Machine.
        """
        super().__init__(charm, "tls")
        self.charm = charm
        self.workload = workload
        self._service_name = service_name
        self.tls_directory_path = tls_directory_path
        self.tls_access = TLSCertificatesRequiresV3(charm, TLS_CERTIFICATE_ACCESS_RELATION_NAME)
        self.certificate_transfer = CertificateTransferProvides(charm, SEND_CA_CERT_RELATION_NAME)

        self.framework.observe(
            self.charm.on[TLS_CERTIFICATE_ACCESS_RELATION_NAME].relation_joined,
            self._on_certificate_config_changed,
        )
        self.framework.observe(
            self.charm.on[TLS_CERTIFICATE_ACCESS_RELATION_NAME].relation_broken,
            self._on_tls_certificates_access_relation_broken,
        )
        self.framework.observe(
            self.tls_access.on.certificate_available,
            self._on_certificate_config_changed,
        )
        self.framework.observe(
            self.tls_access.on.certificate_expiring, self._on_certificate_config_changed
        )
        self.framework.observe(
            self.tls_access.on.certificate_invalidated, self._on_certificate_config_changed
        )
        self.framework.observe(
            self.charm.on[SEND_CA_CERT_RELATION_NAME].relation_joined,
            self._on_certificate_config_changed,
        )

    def _on_certificate_config_changed(self, event: EventBase):
        """Handle TLS configuration changes. Makes the charm reconfigure its environment."""
        self.charm.on.config_changed.emit()

    def _on_tls_certificates_access_relation_broken(self, event: RelationBrokenEvent):
        """Handle leaving the tls access relation.

        Regenerates self signed certificates from the saved self generated root CA
        and reloads vault.
        """
        self._remove_all_certs_from_workload()
        self.charm.on.config_changed.emit()

    def configure_certificates(self, subject_ip: str) -> None:
        """Configure the certificates that are used to connect to and communicate with Vault.

        Args:
            subject_ip: The ip address for which the certificates will be configured for.
        """
        if not self.charm.model.get_relation(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            if self.charm.unit.is_leader() and not self.ca_certificate_secret_exists():
                ca_private_key, ca_certificate = generate_vault_ca_certificate()
                self._set_ca_certificate_secret(ca_private_key, ca_certificate)
                logger.info("Saved the Vault generated CA cert in juju secrets.")
            if (not self.tls_file_pushed_to_workload(File.CA)) or (
                not self.tls_file_pushed_to_workload(File.CERT)
            ):
                self._generate_self_signed_certs(subject_ip)
                logger.info(
                    "Saved Vault generated CA and self signed certificate to %s.",
                    self.charm.unit.name,
                )
                self._restart_vault()
            return

        if self._should_request_new_certificate():
            self._send_new_certificate_request_to_provider(
                self.pull_tls_file_from_workload(File.CSR), subject_ip
            )
            logger.info("CSR for unit %s sent to access relation.", self.charm.unit.name)
        existing_csr = self.pull_tls_file_from_workload(File.CSR)
        signed_cert = self.tls_access._find_certificate_in_relation_data(existing_csr)
        if signed_cert and signed_cert.certificate != self.pull_tls_file_from_workload(File.CERT):
            self._push_tls_file_to_workload(File.CERT, signed_cert.certificate)
            logger.info(
                "Certificate from access relation saved for unit %s.",
                self.charm.unit.name,
            )
            if self.pull_tls_file_from_workload(File.CA) != signed_cert.ca:
                self._push_tls_file_to_workload(File.CA, signed_cert.ca)
                self._restart_vault()
            else:
                self._reload_vault()

    def send_ca_cert(self):
        """Send the existing CA cert in the workload to all relations."""
        if ca := self.pull_tls_file_from_workload(File.CA):
            for relation in self.charm.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                self.certificate_transfer.set_certificate(
                    certificate="", ca=ca, chain=[], relation_id=relation.id
                )
            logger.info("Sent CA certificate to other relations")
        else:
            for relation in self.charm.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                self.certificate_transfer.remove_certificate(relation.id)
            logger.info("Removed CA cert from relations")

    def _generate_self_signed_certs(self, subject_ip: str) -> None:
        """Recreate a unit certificate from the Vault CA certificate, then saves it.

        Args:
            subject_ip: The subject of the unit certificate.
        """
        self._remove_all_certs_from_workload()

        if not (private_key := self.pull_tls_file_from_workload(File.KEY)):
            private_key = generate_private_key().decode()
            self._push_tls_file_to_workload(File.KEY, private_key)

        ca_private_key, ca_certificate = self._get_ca_certificate_secret()
        self._push_tls_file_to_workload(File.CA, ca_certificate)
        sans_ip = [subject_ip]
        certificate = generate_vault_unit_certificate(
            subject=subject_ip,
            sans_ip=sans_ip,
            sans_dns=[socket.getfqdn()],
            ca_certificate=ca_certificate.encode(),
            ca_private_key=ca_private_key.encode(),
            unit_private_key=private_key.encode(),
        )
        self._push_tls_file_to_workload(File.CERT, certificate)

    def _should_request_new_certificate(self) -> bool:
        """Determine if we should request a new certificate from the tls relation."""
        if not self.charm.model.relations.get(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            return False

        csr_is_in_workload = (existing_csr := self.pull_tls_file_from_workload(File.CSR))
        fulfilled_csrs = self.tls_access.get_certificate_signing_requests(fulfilled_only=True)
        pending_csrs = self.tls_access.get_certificate_signing_requests(unfulfilled_only=True)
        expired_certs = self.tls_access.get_expiring_certificates()

        existing_csr_is_fulfilled = any(existing_csr in csr_obj.csr for csr_obj in fulfilled_csrs)
        existing_csr_is_pending = any(existing_csr in csr_obj.csr for csr_obj in pending_csrs)
        existing_csr_expiring = any(
            existing_csr in cert_obj.certificate for cert_obj in expired_certs
        )

        if csr_is_in_workload:
            if existing_csr_is_fulfilled and not existing_csr_expiring:
                return False
            if existing_csr_is_pending:
                return False
        return True

    def _send_new_certificate_request_to_provider(
        self, old_csr: Optional[str], subject_ip: str
    ) -> None:
        """Create and send a new certificate signing request to the provider.

        Args:
            old_csr: Optional value that is used to decide wether to send a renewal or new request.
            subject_ip: string that is the subject of the certificate.
        """
        if not (private_key := self.pull_tls_file_from_workload(File.KEY)):
            private_key = generate_private_key().decode()
            self._push_tls_file_to_workload(File.KEY, private_key)

        new_csr = generate_csr(
            private_key=private_key.encode(),
            subject=subject_ip,
            sans_ip=[subject_ip],
            sans_dns=[socket.getfqdn()],
        )
        self._push_tls_file_to_workload(File.CSR, new_csr.decode())
        if old_csr:
            self.tls_access.request_certificate_renewal(old_csr.encode(), new_csr)
        else:
            self.tls_access.request_certificate_creation(new_csr)

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
        storage = self.charm.model.storages
        if "certs" not in storage:
            raise VaultCertsError()
        if not storage["certs"]:
            raise VaultCertsError()
        cert_storage = storage["certs"][0]
        storage_location = cert_storage.location
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

    def _get_ca_certificate_secret(self) -> Tuple[str, str]:
        """Get the vault CA certificate secret.

        Returns:
            Tuple[Optional[str], Optional[str]]: The CA private key and certificate
        """
        juju_secret = self.charm.model.get_secret(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
        content = juju_secret.get_content(refresh=True)
        return content["privatekey"], content["certificate"]

    def _set_ca_certificate_secret(
        self,
        private_key: str,
        certificate: str,
    ) -> None:
        """Set the vault CA certificate secret.

        Args:
            private_key: Private key
            certificate: certificate
        """
        juju_secret_content = {
            "privatekey": private_key,
            "certificate": certificate,
        }
        if not self.ca_certificate_secret_exists():
            self.charm.app.add_secret(juju_secret_content, label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            logger.debug("Vault CA certificate secret set")
            return
        secret = self.charm.model.get_secret(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
        secret.set_content(juju_secret_content)

    def ca_certificate_secret_exists(self) -> bool:
        """Return whether CA certificate is stored in secret."""
        try:
            ca_private_key, ca_certificate = self._get_ca_certificate_secret()
            if ca_private_key and ca_certificate:
                return True
        except SecretNotFoundError:
            return False
        return False

    def ca_certificate_is_saved(self) -> bool:
        """Return wether a CA cert is saved in the charm."""
        return self.ca_certificate_secret_exists() or self.tls_file_pushed_to_workload(File.CA)

    def _remove_all_certs_from_workload(self) -> None:
        """Remove the certificate files that are used for authentication."""
        self._remove_tls_file_from_workload(File.CA)
        self._remove_tls_file_from_workload(File.CERT)
        self._remove_tls_file_from_workload(File.CSR)
        logger.debug("Removed existing certificate files from workload.")

    def _reload_vault(self) -> None:
        """Send a SIGHUP signal to the process running Vault.

        Reloads Vault's files and fails gracefully.
        """
        try:
            self.workload.send_signal(signal=SIGHUP, process=self._service_name)
            logger.debug("Vault reload requested")
        except Exception:
            logger.debug("Couldn't send signal to process. Proceeding normally.")

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


def generate_vault_ca_certificate() -> Tuple[str, str]:
    """Generate Vault CA certificates valid for 50 years.

    Returns:
        Tuple[str, str]: CA Private key, CA certificate
    """
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        subject=VAULT_CA_SUBJECT,
        validity=365 * 50,
    )

    return ca_private_key.decode(), ca_certificate.decode()


def generate_vault_unit_certificate(
    subject: str,
    sans_ip: List[str],
    sans_dns: List[str],
    ca_certificate: bytes,
    ca_private_key: bytes,
    unit_private_key: bytes,
) -> str:
    """Generate Vault unit certificates valid for 50 years.

    Args:
        subject: Subject of the certificate
        sans_ip: List of IP addresses to add to the SAN
        sans_dns: List of DNS subject alternative names
        ca_certificate: CA certificate
        ca_private_key: CA private key
        unit_private_key: Unit private key

    Returns:
        Tuple[str, str]: Unit private key, Unit certificate
    """
    vault_private_key = generate_private_key() if not unit_private_key else unit_private_key
    csr = generate_csr(
        private_key=vault_private_key, subject=subject, sans_ip=sans_ip, sans_dns=sans_dns
    )
    vault_certificate = generate_certificate(
        ca=ca_certificate,
        ca_key=ca_private_key,
        csr=csr,
        validity=365 * 50,
    )
    return vault_certificate.decode()
