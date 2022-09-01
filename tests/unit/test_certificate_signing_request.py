#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from certificates import generate_csr, generate_private_key

from certificate_signing_request import CertificateSigningRequest


class TestVault(unittest.TestCase):
    def test_given_csr_with_common_name_when_get_common_name_then_common_name_is_returned(self):
        subject = "whatever.com"
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, subject=subject)

        csr = CertificateSigningRequest(certificate_signing_request=csr.decode())

        assert csr.common_name == subject
