# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Common mocking setup for k8s and machine charm unit tests."""

from __future__ import annotations

import contextlib
from typing import Iterator
from unittest.mock import patch

from charms.data_platform_libs.v0.s3 import S3Requirer

from vault.vault_client import VaultClient
from vault.vault_managers import (
    ACMEManager,
    AutounsealProviderManager,
    AutounsealRequirerManager,
    BackupManager,
    KVManager,
    PKIManager,
    TLSManager,
)


class VaultCharmFixturesBase:
    """Base class for VaultCharmFixtures in k8s and machine charms."""

    @contextlib.contextmanager
    def mocks(self) -> Iterator[None]:
        """Set up the common mocks for k8s and machine charms."""
        with contextlib.ExitStack() as stack:
            # When we want to mock the instances, we use the return value of the mocked class
            self.mock_tls = stack.enter_context(
                patch("charm.TLSManager", autospec=TLSManager)
            ).return_value
            self.mock_vault = stack.enter_context(
                patch("charm.VaultClient", autospec=VaultClient)
            ).return_value
            self.mock_vault_autounseal_provider_manager = stack.enter_context(
                patch("charm.AutounsealProviderManager", autospec=AutounsealProviderManager)
            ).return_value
            self.mock_vault_autounseal_requirer_manager = stack.enter_context(
                patch("charm.AutounsealRequirerManager", autospec=AutounsealRequirerManager)
            ).return_value
            self.mock_kv_manager = stack.enter_context(
                patch("charm.KVManager", autospec=KVManager)
            ).return_value
            self.mock_pki_manager = stack.enter_context(
                patch("charm.PKIManager", autospec=PKIManager)
            ).return_value
            self.mock_acme_manager = stack.enter_context(
                patch("charm.ACMEManager", autospec=ACMEManager)
            ).return_value
            self.mock_s3_requirer = stack.enter_context(
                patch("charm.S3Requirer", autospec=S3Requirer)
            ).return_value
            self.mock_backup_manager = stack.enter_context(
                patch("charm.BackupManager", autospec=BackupManager)
            ).return_value
            # When we want to mock the callable, we use the mock directly
            self.mock_socket_fqdn = stack.enter_context(patch("socket.getfqdn"))
            self.mock_get_requirer_assigned_certificate = stack.enter_context(
                patch("charm.TLSCertificatesRequiresV4.get_assigned_certificate")
            )
            self.mock_pki_requirer_renew_certificate = stack.enter_context(
                patch("charm.TLSCertificatesRequiresV4.renew_certificate")
            )
            self.mock_pki_provider_get_outstanding_certificate_requests = stack.enter_context(
                patch("charm.TLSCertificatesProvidesV4.get_outstanding_certificate_requests")
            )
            self.mock_pki_provider_set_relation_certificate = stack.enter_context(
                patch("charm.TLSCertificatesProvidesV4.set_relation_certificate")
            )
            self.mock_autounseal_provides_get_relations_without_credentials = stack.enter_context(
                patch("charm.VaultAutounsealProvides.get_relations_without_credentials")
            )
            self.mock_autounseal_provides_set_data = stack.enter_context(
                patch("charm.VaultAutounsealProvides.set_autounseal_data")
            )
            self.mock_autounseal_requires_get_details = stack.enter_context(
                patch("charm.VaultAutounsealRequires.get_details")
            )
            self.mock_kv_provides_get_credentials = stack.enter_context(
                patch("charm.VaultKvProvides.get_credentials")
            )
            self.mock_kv_provides_set_kv_data = stack.enter_context(
                patch("charm.VaultKvProvides.set_kv_data")
            )
            yield
