#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains all the specificities to communicate with Vault through its API."""

import ipaddress
import logging
from typing import List, Optional, Tuple

import hvac  # type: ignore[import]
import requests

from certificate_signing_request import CertificateSigningRequest

CHARM_POLICY_NAME = "local-charm-policy"
CHARM_ACCESS_ROLE = "local-charm-access"

CHARM_PKI_MOUNT_POINT = "charm-pki-local"
CHARM_PKI_ROLE = "local"


logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Exception raised for Vault errors."""

    pass


class VaultNotReadyError(VaultError):
    """Exception raised for units in error state."""

    def __init__(self, reason):
        message = "Vault is not ready ({})".format(reason)
        super(VaultNotReadyError, self).__init__(message)


class Vault:
    """Class to interact with Vault through its API."""

    def __init__(self, url: str, role_id: Optional[str] = None, secret_id: Optional[str] = None):
        self._client = hvac.Client(url=url)
        if role_id and secret_id:
            self.approle_login(role_id=role_id, secret_id=secret_id)

    @property
    def token(self) -> Optional[str]:
        """Returns Vault's token.

        Returns:
            str: Vault token.
        """
        return self._client.token

    @property
    def is_ready(self) -> bool:
        """Returns whether Vault is ready.

        Returns:
            bool: Whether Vault is ready.
        """
        if not self._is_backend_mounted:
            logger.info("Vault is not ready - Backend not mounted")
            return False
        if not self._client.read("{}/roles/{}".format(CHARM_PKI_MOUNT_POINT, CHARM_PKI_ROLE)):
            logger.info(f"Vault is not ready - Role {CHARM_PKI_ROLE} not created")
            return False
        logger.info("Vault is ready")
        return True

    def set_token(self, token: str) -> None:
        """Sets the Vault token.

        Args:
            token (str): Vault token

        Returns:
            None
        """
        self._client.token = token

    def approle_login(self, role_id: str, secret_id: str) -> None:
        """Logs in to Vault via API.

        Args:
            role_id: Role ID.

        Returns:
            None
        """
        try:
            login_response = self._client.auth.approle.login(
                role_id=role_id, secret_id=secret_id, use_token=False
            )
            self.set_token(token=login_response["auth"]["client_token"])
        except requests.exceptions.ConnectionError:
            logger.error("Login Failed - Can't connect to Vault")

    def enable_approle_auth(self) -> None:
        """Enables AppRole auth method.

        Returns:
            None
        """
        if "approle/" not in self._client.sys.list_auth_methods():
            self._client.sys.enable_auth_method("approle")
            logger.info("Enabled approle auth method")

    def create_local_charm_policy(self) -> None:
        """Add a new policy for the charm.

        Returns:
            None
        """
        with open("src/charm_policy.hcl", "r") as f:
            charm_policy = f.read()
        self._client.sys.create_or_update_policy(name=CHARM_POLICY_NAME, policy=charm_policy)
        logger.info(f"Created charm policy: {CHARM_POLICY_NAME}")

    def create_local_charm_access_approle(self) -> None:
        """Creates approle for charm.

        Returns:
            None
        """
        self._client.auth.approle.create_or_update_approle(
            role_name=CHARM_ACCESS_ROLE,
            token_ttl="60s",
            token_max_ttl="60s",
            token_policies=[CHARM_POLICY_NAME],
        )
        logger.info(f"Created approle {CHARM_ACCESS_ROLE}")

    def get_approle_auth_data(self) -> Tuple[str, str]:
        """Returns Approle authentication data (role_id and secret_id).

        Returns:
            str: Role ID
            str: Secret ID
        """
        role_id_response = self._client.auth.approle.read_role_id(role_name=CHARM_ACCESS_ROLE)
        secret_id_response = self._client.auth.approle.generate_secret_id(
            role_name=CHARM_ACCESS_ROLE
        )
        return role_id_response["data"]["role_id"], secret_id_response["data"]["secret_id"]

    def write_charm_pki_role(
        self,
        allow_any_name=True,
        allowed_domains=None,
        allow_bare_domains=False,
        allow_subdomains=False,
        allow_glob_domains=True,
        enforce_hostnames=False,
        max_ttl="87598h",
    ):
        """Writes role in Vault for the charm to be capable of issuing certificates.

        Args:
            allow_any_name (bool): Specifies if clients can request certs for any CN.
            allowed_domains (list): List of CNs for which clients can request certs.
            allow_bare_domains (bool): Specifies if clients can request certs for CNs exactly
                matching those in allowed_domains.
            allow_subdomains (bool): Specifies if clients can request certificates with CNs that
                are subdomains of those in allowed_domains, including wildcard subdomains.
            allow_glob_domains (bool): Specifies whether CNs in allowed-domains can contain glob
                patterns (e.g., 'ftp*.example.com'), in which case clients will be able to request
                certificates for any CN matching the glob pattern.
            enforce_hostnames (bool): Specifies if only valid host names are allowed for CNs, DNS
                SANs, and the host part of email addresses.
            max_ttl (str): Specifies the maximum Time To Live for generated certs.

        Returns:
            None
        """
        self._write_role(
            role=CHARM_PKI_ROLE,
            allow_any_name=allow_any_name,
            allowed_domains=allowed_domains,
            allow_bare_domains=allow_bare_domains,
            allow_subdomains=allow_subdomains,
            allow_glob_domains=allow_glob_domains,
            enforce_hostnames=enforce_hostnames,
            max_ttl=max_ttl,
        )

    def generate_root_certificate(self, ttl: str = "87599h") -> str:
        """Generating root CA certificate and private key and returning certificate.

        Args:
            ttl: Time to live

        Returns:
            str: Public key of the root certificate.
        """
        config = {
            "common_name": (
                "Vault Root Certificate Authority " "({})".format(CHARM_PKI_MOUNT_POINT)
            ),
            "ttl": ttl,
        }
        root_certificate = self._client.write(
            "{}/root/generate/internal".format(CHARM_PKI_MOUNT_POINT), **config
        )
        if not root_certificate["data"]:
            raise Exception(root_certificate.get("warnings", "unknown error"))
        logger.info("Generated root CA")
        return root_certificate["data"]["certificate"]

    def enable_secrets_engine(
        self, ttl: Optional[str] = None, max_ttl: Optional[str] = None
    ) -> None:
        """Enables Vault's secret engine if the backend is mounted.

        Args:
            ttl (str): Time to live.
            max_ttl (str): Max Time to live.

        Returns:
            None
        """
        self._client.sys.enable_secrets_engine(
            backend_type="pki",
            description="Charm created PKI backend",
            path=CHARM_PKI_MOUNT_POINT,
            config={"default_lease_ttl": ttl or "8759h", "max_lease_ttl": max_ttl or "87600h"},
        )
        logger.info(f"Enabled PKI secrets engine on mount path: {CHARM_PKI_MOUNT_POINT}")

    @property
    def _is_backend_mounted(self) -> bool:
        """Check if the supplied backend is mounted.

        Returns:
            bool: Whether mount point is in use
        """
        return (
            "{}/".format(CHARM_PKI_MOUNT_POINT) in self._client.sys.list_mounted_secrets_engines()
        )

    def _write_role(self, role: str, **kwargs) -> None:
        """Writes role in Vault.

        Args:
            role (str): Role
            **kwargs: Other keyword arguments

        Returns:
            None
        """
        self._client.write("{}/roles/{}".format(CHARM_PKI_MOUNT_POINT, role), **kwargs)
        logger.info(f"Wrote role for PKI access: {role}")

    def issue_certificate(self, certificate_signing_request: str) -> dict:
        """Issues a certificate based on a provided CSR.

        Args:
            certificate_signing_request: Certificate Signing Request

        Returns:
            dict: certificate data
        """
        csr_object = CertificateSigningRequest(certificate_signing_request)
        config = {
            "common_name": csr_object.common_name,
            "csr": certificate_signing_request,
            "format": "pem",
        }
        return self._issue_certificate(**config)

    def _issue_certificate(self, **config) -> dict:
        """Issues a certificate based on a provided CSR.

        Args:
            role (str): Vault role
        """
        try:
            response = self._client.write(
                path=f"{CHARM_PKI_MOUNT_POINT}/sign/{CHARM_PKI_ROLE}", **config
            )
        except hvac.exceptions.InvalidRequest as e:
            raise RuntimeError(str(e)) from e
        if not response["data"]:
            raise RuntimeError(response.get("warnings", "unknown error"))
        logger.info(f"Issued certificate with role {CHARM_PKI_ROLE} for config: {config}")
        return response["data"]

    @staticmethod
    def _sort_sans(sans: list) -> Tuple[List, List]:
        """Split SANs into IP SANs and name SANs.

        Args:
            sans (list): List of SANs

        Returns:
            A tuple containing, a list of IP SAN's and a list of name SAN's.
        """
        ip_sans = set()
        for san in sans:
            try:
                ipaddress.ip_address(san)
                ip_sans.add(san)
            except ValueError:
                pass
        alt_names = set(sans).difference(ip_sans)
        return sorted(list(ip_sans)), sorted(list(alt_names))
