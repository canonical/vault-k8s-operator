# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.vault_k8s.v0.vault_client import (
    Vault,
)
from charms.vault_k8s.v0.vault_s3 import S3
from charms.vault_k8s.v0.vault_tls import VaultTLSManager

from charm import VaultCharm


class VaultCharmFixtures:
    patcher_tls = patch("charm.VaultTLSManager", autospec=VaultTLSManager)
    patcher_vault = patch("charm.Vault", autospec=Vault)
    patcher_s3_requirer = patch("charm.S3Requirer", autospec=S3Requirer)
    patcher_s3 = patch("charm.S3", autospec=S3)
    patcher_socket_fqdn = patch("socket.getfqdn")

    @pytest.fixture(autouse=True)
    def setup(self):
        self.mock_tls = VaultCharmFixtures.patcher_tls.start().return_value
        self.mock_vault = VaultCharmFixtures.patcher_vault.start().return_value
        self.mock_s3_requirer = VaultCharmFixtures.patcher_s3_requirer.start().return_value
        self.mock_s3 = VaultCharmFixtures.patcher_s3.start()
        self.mock_socket_fqdn = VaultCharmFixtures.patcher_socket_fqdn.start()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=VaultCharm,
        )
