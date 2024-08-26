# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.vault_k8s.v0.vault_client import Vault
from charms.vault_k8s.v0.vault_s3 import S3
from charms.vault_k8s.v0.vault_tls import VaultTLSManager

from charm import VaultCharm

TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"


class VaultCharmFixtures:
    patcher_tls = patch("charm.VaultTLSManager", autospec=VaultTLSManager)
    patcher_vault = patch("charm.Vault", autospec=Vault)
    patcher_s3_requirer = patch("charm.S3Requirer", autospec=S3Requirer)
    patcher_s3 = patch("charm.S3", autospec=S3)
    patcher_socket_fqdn = patch("socket.getfqdn")
    patcher_pki_requirer_request_certificate_creation = patch(
        f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    patcher_pki_requirer_get_assigned_certificates = patch(
        f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates"
    )
    patcher_pki_provider_get_outstanding_certificate_requests = patch(
        f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.get_outstanding_certificate_requests"
    )
    patcher_pki_provider_set_relation_certificate = patch(
        f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate"
    )

    @pytest.fixture(autouse=True)
    def setup(self):
        self.mock_tls = VaultCharmFixtures.patcher_tls.start().return_value
        self.mock_vault = VaultCharmFixtures.patcher_vault.start().return_value
        self.mock_s3_requirer = VaultCharmFixtures.patcher_s3_requirer.start().return_value
        self.mock_s3 = VaultCharmFixtures.patcher_s3.start()
        self.mock_socket_fqdn = VaultCharmFixtures.patcher_socket_fqdn.start()
        self.mock_pki_requirer_request_certificate_creation = (
            VaultCharmFixtures.patcher_pki_requirer_request_certificate_creation.start()
        )
        self.mock_pki_requirer_get_assigned_certificates = (
            VaultCharmFixtures.patcher_pki_requirer_get_assigned_certificates.start()
        )
        self.mock_pki_provider_get_outstanding_certificate_requests = (
            VaultCharmFixtures.patcher_pki_provider_get_outstanding_certificate_requests.start()
        )
        self.mock_pki_provider_set_relation_certificate = (
            VaultCharmFixtures.patcher_pki_provider_set_relation_certificate.start()
        )

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=VaultCharm,
        )
