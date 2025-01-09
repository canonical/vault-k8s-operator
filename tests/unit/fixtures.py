# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import ops.testing as testing
import pytest
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.vault_k8s.v0.vault_client import (
    VaultClient,
)
from charms.vault_k8s.v0.vault_managers import (
    AutounsealProviderManager,
    AutounsealRequirerManager,
    BackupManager,
    KVManager,
    PKIManager,
    TLSManager,
)

from charm import VaultCharm


class VaultCharmFixtures:
    @pytest.fixture(autouse=True)
    def setup(self):
        with (
            patch("charm.TLSManager", autospec=TLSManager) as mock_tls,
            patch("charm.VaultClient", autospec=VaultClient) as mock_vault,
            patch(
                "charm.AutounsealProviderManager", autospec=AutounsealProviderManager
            ) as mock_autounseal_provider_manager,
            patch(
                "charm.AutounsealRequirerManager", autospec=AutounsealRequirerManager
            ) as mock_autounseal_requirer_manager,
            patch("charm.KVManager", autospec=KVManager) as mock_kv_manager,
            patch("charm.PKIManager", autospec=PKIManager) as mock_pki_manager,
            patch("charm.S3Requirer", autospec=S3Requirer) as mock_s3_requirer,
            patch("charm.BackupManager", autospec=BackupManager) as mock_backup_manager,
            patch("socket.getfqdn") as mock_socket_fqdn,
            patch(
                "charm.TLSCertificatesRequiresV4.get_assigned_certificate"
            ) as mock_pki_requirer_get_assigned_certificate,
            patch(
                "charm.TLSCertificatesRequiresV4.renew_certificate"
            ) as mock_pki_requirer_renew_certificate,
            patch(
                "charm.TLSCertificatesProvidesV4.get_outstanding_certificate_requests"
            ) as mock_pki_provider_get_outstanding_certificate_requests,
            patch(
                "charm.TLSCertificatesProvidesV4.set_relation_certificate"
            ) as mock_pki_provider_set_relation_certificate,
            patch(
                "charm.VaultAutounsealProvides.get_relations_without_credentials"
            ) as mock_autounseal_provides_get_relations_without_credentials,
            patch(
                "charm.VaultAutounsealProvides.set_autounseal_data"
            ) as mock_autounseal_provides_set_data,
            patch(
                "charm.VaultAutounsealRequires.get_details"
            ) as mock_autounseal_requires_get_details,
            patch("charm.VaultKvProvides.get_credentials") as mock_kv_provides_get_credentials,
            patch("charm.VaultKvProvides.set_kv_data") as mock_kv_provides_set_kv_data,
            patch("ops.model.Model.get_binding") as mock_get_binding,
        ):
            # When we want to mock the instances, we use the return value of
            # the mock
            self.mock_tls = mock_tls.return_value
            self.mock_vault = mock_vault.return_value
            self.mock_vault_autounseal_provider_manager = (
                mock_autounseal_provider_manager.return_value
            )
            self.mock_vault_autounseal_requirer_manager = (
                mock_autounseal_requirer_manager.return_value
            )
            self.mock_kv_manager = mock_kv_manager.return_value
            self.mock_pki_manager = mock_pki_manager.return_value
            self.mock_s3_requirer = mock_s3_requirer.return_value
            self.mock_backup_manager = mock_backup_manager.return_value

            # When we want to mock the callable, we use the mock directly
            self.mock_socket_fqdn = mock_socket_fqdn
            self.mock_pki_requirer_get_assigned_certificate = (
                mock_pki_requirer_get_assigned_certificate
            )
            self.mock_pki_requirer_renew_certificate = mock_pki_requirer_renew_certificate
            self.mock_pki_provider_get_outstanding_certificate_requests = (
                mock_pki_provider_get_outstanding_certificate_requests
            )
            self.mock_pki_provider_set_relation_certificate = (
                mock_pki_provider_set_relation_certificate
            )
            self.mock_autounseal_provides_get_relations_without_credentials = (
                mock_autounseal_provides_get_relations_without_credentials
            )
            self.mock_autounseal_provides_set_data = mock_autounseal_provides_set_data
            self.mock_autounseal_requires_get_details = mock_autounseal_requires_get_details
            self.mock_kv_provides_get_credentials = mock_kv_provides_get_credentials
            self.mock_kv_provides_set_kv_data = mock_kv_provides_set_kv_data
            self.mock_get_binding = mock_get_binding
            yield

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultCharm,
        )


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)
