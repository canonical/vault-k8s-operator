#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains method used to retrieve useful information from a given csr."""

from typing import Literal

from cryptography import x509


class CertificateSigningRequest:
    """Certificate Signing Request class."""

    def __init__(self, certificate_signing_request: str):
        self.csr = x509.load_pem_x509_csr(certificate_signing_request.encode())

    @property
    def common_name(self) -> str:
        """Returns attribute 'CN'."""
        for i in self.csr.subject:
            if i.rfc4514_attribute_name == "CN":
                return str(i.value)
        raise ValueError("No common name in CSR")

    @property
    def certificate_type(self) -> Literal["server", "client"]:
        """Returns certificate type."""
        for extension in self.csr.extensions:
            if isinstance(extension.value, x509.ExtendedKeyUsage):
                if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in extension.value._usages:
                    return "server"
                if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in extension.value._usages:
                    return "client"
        return "server"
