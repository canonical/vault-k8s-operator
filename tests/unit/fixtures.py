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
    patcher_tls = patch("charm.TLSManager", autospec=TLSManager)
    patcher_vault = patch("charm.VaultClient", autospec=VaultClient)
    patcher_vault_autounseal_provider_manager = patch(
        "charm.AutounsealProviderManager", autospec=AutounsealProviderManager
    )
    patcher_vault_autounseal_requirer_manager = patch(
        "charm.AutounsealRequirerManager", autospec=AutounsealRequirerManager
    )
    patcher_kv_manager = patch("charm.KVManager", autospec=KVManager)
    patcher_pki_manager = patch("charm.PKIManager", autospec=PKIManager)
    patcher_s3_requirer = patch("charm.S3Requirer", autospec=S3Requirer)
    patcher_backup_manager = patch("charm.BackupManager", autospec=BackupManager)
    patcher_socket_fqdn = patch("socket.getfqdn")
    patcher_pki_requirer_get_assigned_certificate = patch(
        "charm.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    patcher_pki_requirer_renew_certificate = patch(
        "charm.TLSCertificatesRequiresV4.renew_certificate"
    )
    patcher_pki_provider_get_outstanding_certificate_requests = patch(
        "charm.TLSCertificatesProvidesV4.get_outstanding_certificate_requests"
    )
    patcher_pki_provider_set_relation_certificate = patch(
        "charm.TLSCertificatesProvidesV4.set_relation_certificate"
    )
    patcher_autounseal_provides_get_relations_without_credentials = patch(
        "charm.VaultAutounsealProvides.get_relations_without_credentials"
    )
    patcher_autounseal_provides_set_data = patch(
        "charm.VaultAutounsealProvides.set_autounseal_data"
    )
    patcher_autounseal_requires_get_details = patch("charm.VaultAutounsealRequires.get_details")
    patcher_kv_provides_get_credentials = patch("charm.VaultKvProvides.get_credentials")
    patcher_kv_provides_set_kv_data = patch("charm.VaultKvProvides.set_kv_data")
    patcher_get_binding = patch("ops.model.Model.get_binding")

    @pytest.fixture(autouse=True)
    def setup(self):
        self.mock_tls = VaultCharmFixtures.patcher_tls.start().return_value
        self.mock_vault = VaultCharmFixtures.patcher_vault.start().return_value
        self.mock_vault_autounseal_manager = (
            VaultCharmFixtures.patcher_vault_autounseal_provider_manager.start().return_value
        )
        self.mock_vault_autounseal_requirer_manager = (
            VaultCharmFixtures.patcher_vault_autounseal_requirer_manager.start().return_value
        )
        self.mock_kv_manager = VaultCharmFixtures.patcher_kv_manager.start().return_value
        self.mock_pki_manager = VaultCharmFixtures.patcher_pki_manager.start().return_value
        self.mock_s3_requirer = VaultCharmFixtures.patcher_s3_requirer.start().return_value
        self.mock_backup_manager = VaultCharmFixtures.patcher_backup_manager.start().return_value
        self.mock_socket_fqdn = VaultCharmFixtures.patcher_socket_fqdn.start()
        self.mock_pki_requirer_get_assigned_certificate = (
            VaultCharmFixtures.patcher_pki_requirer_get_assigned_certificate.start()
        )
        self.mock_pki_requirer_renew_certificate = (
            VaultCharmFixtures.patcher_pki_requirer_renew_certificate.start()
        )
        self.mock_pki_provider_get_outstanding_certificate_requests = (
            VaultCharmFixtures.patcher_pki_provider_get_outstanding_certificate_requests.start()
        )
        self.mock_pki_provider_set_relation_certificate = (
            VaultCharmFixtures.patcher_pki_provider_set_relation_certificate.start()
        )
        self.mock_autounseal_provides_get_relations_without_credentials = VaultCharmFixtures.patcher_autounseal_provides_get_relations_without_credentials.start()
        self.mock_autounseal_provides_set_data = (
            VaultCharmFixtures.patcher_autounseal_provides_set_data.start()
        )
        self.mock_autounseal_requires_get_details = (
            VaultCharmFixtures.patcher_autounseal_requires_get_details.start()
        )
        self.mock_kv_provides_get_credentials = (
            VaultCharmFixtures.patcher_kv_provides_get_credentials.start()
        )
        self.mock_kv_provides_set_kv_data = (
            VaultCharmFixtures.patcher_kv_provides_set_kv_data.start()
        )
        self.mock_get_binding = VaultCharmFixtures.patcher_get_binding.start()
        self.mock_pki_requirer_renew_certificate = (
            VaultCharmFixtures.patcher_pki_requirer_renew_certificate.start()
        )

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
