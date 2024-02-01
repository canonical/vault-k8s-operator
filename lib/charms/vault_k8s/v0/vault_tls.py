# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""This file includes methods to manage TLS certificates within the Vault charms."""

import logging
import socket
from enum import Enum, auto
from signal import SIGHUP
from typing import List, Optional, TextIO, Tuple

from charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.tls_certificates_interface.v2.tls_certificates import (
    TLSCertificatesRequiresV2,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import EventBase, Object, RelationBrokenEvent, SecretNotFoundError
from ops.pebble import APIError, PathError

from exceptions import PeerSecretError, VaultCertsError

# The unique Charmhub library identifier, never change it
LIBID = "61b41a053d9847ce8a14eb02197d12cb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class TLSAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend TLS to all log lines."""

    def process(self, msg, kwargs):
        """Decides the format for the prepended text."""
        return f"[TLS] {msg}", kwargs


tlslogger = TLSAdapter(logger, {})

SEND_CA_CERT_RELATION_NAME = "send-ca-cert"
TLS_CERTIFICATE_ACCESS_RELATION_NAME = "tls-certificates-access"
TLS_FILE_FOLDER_PATH = "/vault/certs"
CA_CERTIFICATE_JUJU_SECRET_KEY = "vault-ca-certificates-secret-id"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "vault-ca-certificate"

VAULT_CA_SUBJECT = "Vault self signed CA"


class Substrate(Enum):
    """Determines which type of charm this library is running in.

    Some library functions need to interact with the substrate by reading and writing files. This
    enum allows the library to make the correct decision on which methods to use depending on the
    substrate.
    """

    KUBERNETES = "kubernetes"
    MACHINE = "machine"


class File(Enum):
    """This enum determines which files are expected of the library to read."""

    CERT = auto()
    KEY = auto()
    CA = auto()
    CSR = auto()


class VaultTLSManager(Object):
    """This class configures the certificates within Vault."""

    def __init__(self, charm, peer_relation: str, substrate: Substrate):
        """Manager of TLS relation and configuration."""
        super().__init__(charm, "tls")
        self.charm = charm
        self.substrate = substrate
        self.peer_relation = peer_relation
        self.tls_access = TLSCertificatesRequiresV2(charm, TLS_CERTIFICATE_ACCESS_RELATION_NAME)
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
            self.tls_access.on.certificate_available, self._on_certificate_config_changed
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
        """Handles leaving the tls access relation.

        Regenerates self signed certificates from the saved self generated root CA
        and reloads vault.
        """
        self._remove_all_certs_from_workload()
        if not self.charm._ingress_address:
            return
        self._generate_self_signed_certs(self.charm._ingress_address)
        tlslogger.info(
            "Saved Vault generated CA and self signed certificate to %s.",
            self.charm.unit.name,
        )
        self._reload_vault_container()

    def configure_certificates(self, ingress_address: str) -> None:
        """Configures the certificates that are used to connect to and communicate with Vault.

        Args:
            ingress_address: The ip address for which the certificates will be configured for.
        """
        if self.charm.unit.is_leader() and not self.ca_certificate_set_in_peer_relation():
            ca_private_key, ca_certificate = generate_vault_ca_certificate()
            self._set_ca_certificate_secret_in_peer_relation(ca_private_key, ca_certificate)
            tlslogger.info("Saved the Vault generated CA cert in juju secrets.")

        if not self._tls_file_pushed_to_workload(File.CA) or not self._tls_file_pushed_to_workload(
            File.CERT
        ):
            self._generate_self_signed_certs(ingress_address)
            tlslogger.info(
                "Saved Vault generated CA and self signed certificate to %s.",
                self.charm.unit.name,
            )
            self._reload_vault_container()

        elif self.charm.model.get_relation(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            if self._should_request_new_certificate():
                self._send_new_certificate_request_to_provider(
                    self.pull_tls_file_from_workload(File.CSR), ingress_address
                )
                tlslogger.info("CSR for unit %s sent to access relation.", self.charm.unit.name)

            existing_csr = self.pull_tls_file_from_workload(File.CSR)
            assigned_cert = self.tls_access._find_certificate_in_relation_data(existing_csr)
            if assigned_cert and assigned_cert["certificate"] != self.pull_tls_file_from_workload(
                File.CERT
            ):
                self._push_tls_file_to_workload(File.CERT, assigned_cert["certificate"])
                self._push_tls_file_to_workload(File.CA, assigned_cert["ca"])
                tlslogger.info(
                    "Certificate from access relation saved for unit %s.",
                    self.charm.unit.name,
                )
                self._reload_vault_container()
                return

    def send_ca_cert(self):
        """Sends the existing CA cert in the workload to all relations."""
        if ca := self.pull_tls_file_from_workload(File.CA):
            for relation in self.charm.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                self.certificate_transfer.set_certificate(
                    certificate="", ca=ca, chain=[], relation_id=relation.id
                )
            tlslogger.info("Sent CA certificate to other relations")
        else:
            for relation in self.charm.model.relations.get(SEND_CA_CERT_RELATION_NAME, []):
                self.certificate_transfer.remove_certificate(relation.id)
            tlslogger.info("Removed CA cert from relations")

    def _generate_self_signed_certs(self, ingress_address: str) -> None:
        """Recreates a unit certificate from the Vault CA certificate, then saves it.

        Args:
            ingress_address: The subject of the unit certificate.
        """
        self._remove_all_certs_from_workload()

        if not (private_key := self.pull_tls_file_from_workload(File.KEY)):
            private_key = generate_private_key().decode()
            self._push_tls_file_to_workload(File.KEY, private_key)

        ca_private_key, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
        self._push_tls_file_to_workload(File.CA, ca_certificate)
        sans_ip = [ingress_address]
        certificate = generate_vault_unit_certificate(
            subject=ingress_address,
            sans_ip=sans_ip,
            sans_dns=[socket.getfqdn()],
            ca_certificate=ca_certificate.encode(),
            ca_private_key=ca_private_key.encode(),
            unit_private_key=private_key.encode(),
        )
        self._push_tls_file_to_workload(File.CERT, certificate)

    def _should_request_new_certificate(self) -> bool:
        """Determines if we should request a new certificate from the tls relation."""
        if not self.charm.model.relations.get(TLS_CERTIFICATE_ACCESS_RELATION_NAME):
            return False

        csr_is_in_workload = (existing_csr := self.pull_tls_file_from_workload(File.CSR))
        fulfilled_csrs = self.tls_access.get_certificate_signing_requests(fulfilled_only=True)
        pending_csrs = self.tls_access.get_certificate_signing_requests(unfulfilled_only=True)
        expired_certs = self.tls_access.get_expiring_certificates()

        existing_csr_is_fulfilled = any([existing_csr in csr.values() for csr in fulfilled_csrs])
        existing_csr_is_pending = any([existing_csr in csr.values() for csr in pending_csrs])
        existing_csr_expiring = any([existing_csr in cert.values() for cert in expired_certs])

        if csr_is_in_workload:
            if existing_csr_is_fulfilled and not existing_csr_expiring:
                return False
            if existing_csr_is_pending:
                return False
        return True

    def _send_new_certificate_request_to_provider(
        self, old_csr: Optional[str], ingress_address: str
    ) -> None:
        """This function creates and sends a new certificate signing request to the provider.

        Args:
            old_csr: Optional value that is used to decide wether to send a renewal or new request.
            ingress_address: string that is the subject of the certificate.
        """
        if not (private_key := self.pull_tls_file_from_workload(File.KEY)):
            private_key = generate_private_key().decode()
            self._push_tls_file_to_workload(File.KEY, private_key)

        new_csr = generate_csr(
            private_key=private_key.encode(),
            subject=ingress_address,
            sans_ip=[ingress_address],
            sans_dns=[socket.getfqdn()],
        )
        self._push_tls_file_to_workload(File.CSR, new_csr.decode())
        if old_csr:
            self.tls_access.request_certificate_renewal(old_csr.encode(), new_csr)
        else:
            self.tls_access.request_certificate_creation(new_csr)

    def get_tls_file_path_in_charm(self, file: File) -> str:
        """Returns the requested file's location in the charm (not in the workload).

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

    def _get_ca_certificate_secret_in_peer_relation(self) -> Tuple[str, str]:
        """Get the vault CA certificate secret from the peer relation.

        Returns:
            Tuple[Optional[str], Optional[str]]: The CA private key and certificate
        """
        try:
            peer_relation = self.charm.model.get_relation(self.peer_relation)
            juju_secret_id = peer_relation.data[peer_relation.app].get(
                CA_CERTIFICATE_JUJU_SECRET_KEY
            )
            juju_secret = self.charm.model.get_secret(id=juju_secret_id)
            content = juju_secret.get_content()
            return content["privatekey"], content["certificate"]
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name=CA_CERTIFICATE_JUJU_SECRET_KEY)

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
        if not self.charm._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        juju_secret_content = {
            "privatekey": private_key,
            "certificate": certificate,
        }
        juju_secret = self.charm.app.add_secret(
            juju_secret_content, label=CA_CERTIFICATE_JUJU_SECRET_LABEL
        )
        peer_relation = self.charm.model.get_relation(self.peer_relation)
        peer_relation.data[self.charm.app].update({CA_CERTIFICATE_JUJU_SECRET_KEY: juju_secret.id})
        tlslogger.debug("Vault CA certificate secret set in peer relation")

    def _remove_ca_certificate_secret_in_peer_relation(self) -> None:
        """Removes the vault CA certificate secret in the peer relation.

        Only the key from the relation is removed. The actual juju secret is unmodified.
        """
        if not self.charm._is_peer_relation_created():
            raise RuntimeError("Peer relation not created")
        peer_relation = self.model.get_relation(self.peer_relation)
        if peer_relation:
            peer_relation.data[self.charm.app].pop(CA_CERTIFICATE_JUJU_SECRET_KEY)
            tlslogger.debug("Vault CA certificate secret removed from peer relation")

    def ca_certificate_set_in_peer_relation(self) -> bool:
        """Returns whether CA certificate is stored in peer relation data."""
        try:
            ca_private_key, ca_certificate = self._get_ca_certificate_secret_in_peer_relation()
            if ca_private_key and ca_certificate:
                return True
        except PeerSecretError:
            return False
        return False

    """TODO: The following are methods that go through the container.
    They will be extracted out in the future."""

    def _remove_all_certs_from_workload(self) -> None:
        """Removes the certificate files that are used for authentication."""
        self._remove_tls_file_from_workload(File.CA)
        self._remove_tls_file_from_workload(File.CERT)
        self._remove_tls_file_from_workload(File.CSR)
        tlslogger.debug("Removed existing certificate files from workload.")

    def _reload_vault_container(self) -> None:
        """Sends a SIGHUP signal to the container which reloads Vault's files. Fails gracefully."""
        try:
            self.charm._container.send_signal(SIGHUP, self.charm._container_name)
            tlslogger.debug("Container restart requested")
        except APIError:
            tlslogger.debug("Couldn't send signal to container. Proceeding normally.")

    def pull_tls_file_from_workload(self, file: File) -> str:
        """Get a file related to certs from the container.

        Args:
            file: a File object that determines which file to read.

        Returns:
            str: The file content without whitespace.
        """
        try:
            file_content: TextIO = self.charm._container.pull(
                f"{TLS_FILE_FOLDER_PATH}/{file.name.lower()}.pem",
            )
        except PathError:
            return ""
        return file_content.read().strip()

    def _push_tls_file_to_workload(self, file: File, data: str) -> None:
        """Push one of the given file types to the workload.

        Args:
            file: a File object that determines which file to write.
            data: the data to write into that file.
        """
        self.charm._container.push(
            path=f"{TLS_FILE_FOLDER_PATH}/{file.name.lower()}.pem", source=data
        )
        tlslogger.debug("Pushed %s file to workload", file.name)

    def _remove_tls_file_from_workload(self, file: File) -> None:
        """Removes the certificate files that are used for authentication.

        Args:
            file: a File object that determines which file to remove.
        """
        try:
            self.charm._container.remove_path(f"{TLS_FILE_FOLDER_PATH}/{file.name.lower()}.pem")
        except PathError:
            pass
        tlslogger.debug("Removed %s file from workload.", file.name)

    def _tls_file_pushed_to_workload(self, file: File) -> bool:
        """Returns whether tls file is pushed to the workload.

        Args:
            file: a File object that determines which file to check.

        Returns:
            bool: True if file exists.
        """
        return self.charm._container.exists(path=f"{TLS_FILE_FOLDER_PATH}/{file.name.lower()}.pem")


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
