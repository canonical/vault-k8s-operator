#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import textwrap
import unittest
from unittest.mock import patch

from charms.vault_k8s.v0.vault_autounseal import (
    VaultAutounsealDestroy,
    VaultAutounsealDetailsReadyEvent,
    VaultAutounsealInitialize,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from ops import testing
from ops.charm import CharmBase

AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"


class VaultAutounsealProviderCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-autounseal-provider
        containers:
          vault:
            resource: vault-image
        provides:
          vault-autounseal-provides:
            interface: vault-autounseal
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultAutounsealProvides(self, AUTOUNSEAL_PROVIDES_RELATION_NAME)
        self.framework.observe(
            self.interface.on.vault_autounseal_initialize, self._on_vault_autounseal_initialize
        )
        self.framework.observe(
            self.interface.on.vault_autounseal_destroy, self._on_vault_autounseal_initialize
        )

    def _on_vault_autounseal_initialize(self, event: VaultAutounsealInitialize):
        pass

    def _on_vault_autounseal_destroy(self, event: VaultAutounsealDestroy):
        pass


class VaultAutounsealRequirerCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-autounseal-requirer
        containers:
          vault:
            resource: vault-image
        requires:
          vault-autounseal-requires:
            interface: vault-autounseal
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultAutounsealRequires(self, AUTOUNSEAL_REQUIRES_RELATION_NAME)
        self.framework.observe(
            self.interface.on.vault_autounseal_details_ready, self._on_details_ready
        )

    def _on_details_ready(self, event: VaultAutounsealDetailsReadyEvent):
        pass


class TestVaultAutounsealProvides(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultAutounsealProviderCharm, meta=VaultAutounsealProviderCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, leader: bool = True) -> tuple:
        """Set up a relation between the charm and a remote app with 1 unit."""
        remote_app = "vault-autounseal-requires"
        remote_unit = remote_app + "/0"
        rel_name = AUTOUNSEAL_PROVIDES_RELATION_NAME
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        return remote_app, remote_unit, relation, rel_id

    def test_given_unit_is_leader_when_set_vault_url_then_relation_data_is_updated(self):
        _, _, relation, rel_id = self.setup_relation()
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert (
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)["address"]
            == vault_url
        )

    def test_given_unit_is_not_leader_when_set_vault_url_then_relation_data_is_not_updated(self):
        _, _, relation, rel_id = self.setup_relation(leader=False)
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert "address" not in self.harness.get_relation_data(rel_id, self.harness.charm.app.name)

    def test_when_set_credentials_secret_id_then_relation_data_is_updated(self):
        _, _, relation, rel_id = self.setup_relation()

        self.harness.charm.interface.set_credentials_secret_id(relation, "some secret id")

        assert (
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)[
                "credentials_secret_id"
            ]
            == "some secret id"
        )

    def test_when_set_ca_certificate_then_relation_data_is_updated(self):
        _, _, relation, rel_id = self.setup_relation()

        self.harness.charm.interface.set_ca_certificate(relation, "some ca certificate")

        assert (
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)["ca_certificate"]
            == "some ca certificate"
        )
