#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains method used to retrieve useful information from a given csr."""

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
