#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from certificates import generate_csr, generate_private_key
from cryptography import x509

from certificate_signing_request import CertificateSigningRequest


class TestVault(unittest.TestCase):
    def test_given_csr_with_common_name_when_get_common_name_then_common_name_is_retured(self):
        subject = "whatever.com"
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, subject=subject)

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.common_name == subject

    def test_given_csr_has_server_in_enhanced_key_usages_when_certificate_type_then_client_is_retured(  # noqa: E501
        self,
    ):
        subject = "whatever.com"
        private_key = generate_private_key()
        extensions = [x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])]
        csr = generate_csr(
            private_key=private_key, subject=subject, additional_critical_extensions=extensions
        )

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.certificate_type == "client"

    def test_given_csr_has_client_in_enhanced_key_usages_when_get_certificate_type_then_client_is_retured(  # noqa: E501
        self,
    ):
        subject = "whatever.com"
        private_key = generate_private_key()
        extensions = [x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])]
        csr = generate_csr(
            private_key=private_key, subject=subject, additional_critical_extensions=extensions
        )

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.certificate_type == "server"

    def test_given_csr_has_both_client_in_server_in_enhanced_key_usages_when_get_certificate_type_then_server_is_returned(  # noqa: E501
        self,
    ):
        subject = "whatever.com"
        private_key = generate_private_key()
        extensions = [
            x509.ExtendedKeyUsage(
                usages=[
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
        ]
        csr = generate_csr(
            private_key=private_key, subject=subject, additional_critical_extensions=extensions
        )

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.certificate_type == "server"

    def test_given_csr_has_no_enhanced_key_usages_when_get_certificate_type_then_server_is_returned(  # noqa: E501
        self,
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, subject="whatever.com")

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.certificate_type == "server"
