#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

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
        return remote_app, remote_unit, relation

    def test_given_unit_is_leader_when_set_vault_url_then_relation_data_is_updated(self):
        _, _, relation = self.setup_relation()
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert (
            self.harness.get_relation_data(relation.id, self.harness.charm.app.name)["address"]
            == vault_url
        )

    def test_given_unit_is_not_leader_when_set_vault_url_then_relation_data_is_not_updated(self):
        _, _, relation = self.setup_relation(leader=False)
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert "address" not in self.harness.get_relation_data(
            relation.id, self.harness.charm.app.name
        )

    def test_when_set_credentials_secret_id_then_relation_data_is_updated(self):
        _, _, relation = self.setup_relation()

        self.harness.charm.interface.set_credentials_secret_id(relation, "some secret id")

        assert (
            self.harness.get_relation_data(relation.id, self.harness.charm.app.name)[
                "credentials_secret_id"
            ]
            == "some secret id"
        )

    def test_when_set_ca_certificate_then_relation_data_is_updated(self):
        _, _, relation = self.setup_relation()

        self.harness.charm.interface.set_ca_certificate(relation, "some ca certificate")

        assert (
            self.harness.get_relation_data(relation.id, self.harness.charm.app.name)[
                "ca_certificate"
            ]
            == "some ca certificate"
        )


class TestVaultAutounsealRequires(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultAutounsealRequirerCharm, meta=VaultAutounsealRequirerCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, leader: bool = True) -> tuple:
        """Set up a relation between the charm and a remote app with 1 unit."""
        remote_app = "vault-autounseal-provider"
        remote_unit = remote_app + "/0"
        rel_name = AUTOUNSEAL_REQUIRES_RELATION_NAME
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        return remote_app, remote_unit, relation

    @patch("test_vault_autounseal.VaultAutounsealRequirerCharm._on_details_ready")
    def test_given_unit_joined_when_all_data_present_then_vault_auto_unseal_details_ready_event_is_fired(
        self, _on_details_ready
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        vault_url = "https://vault.example.com"
        credentials_secret_id = "some secret id"
        ca_certificate = "some ca certificate"
        self.harness.update_relation_data(
            relation.id,
            remote_app,
            {
                "address": vault_url,
                "credentials_secret_id": credentials_secret_id,
                "ca_certificate": ca_certificate,
            },
        )

        args, _ = _on_details_ready.call_args
        event = args[0]

        assert isinstance(event, VaultAutounsealDetailsReadyEvent)
        assert event.relation.id == relation.id
        assert event.relation.name == relation.name

    @patch("test_vault_autounseal.VaultAutounsealRequirerCharm._on_details_ready")
    def test_given_unit_joined_when_data_missing_then_vault_auto_unseal_details_ready_event_not_fired(
        self, _on_details_ready
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        vault_url = "https://vault.example.com"
        credentials_secret_id = "some secret id"
        self.harness.update_relation_data(
            relation.id,
            remote_app,
            {
                "address": vault_url,
                "credentials_secret_id": credentials_secret_id,
                # "ca_certificate": Missing!
            },
        )

        _on_details_ready.assert_not_called()

    def test_when_get_credentials_secret_id_then_returns_secret_id(self):
        remote_app, remote_unit, relation = self.setup_relation()
        self.harness.update_relation_data(
            relation.id, remote_app, {"credentials_secret_id": "some secret id"}
        )

        secret_id = self.harness.charm.interface.get_credentials_secret_id(relation)
        assert secret_id == "some secret id"

    def test_when_get_credentials_then_returns_credentials(self):
        secret_id = self.harness.add_model_secret(
            self.harness.charm.app, {"role-id": "some role id", "secret-id": "some secret id"}
        )

        credentials = self.harness.charm.interface.get_credentials(secret_id)
        assert credentials == ("some role id", "some secret id")

    def test_when_get_ca_certificate_then_returns_ca_certificate(self):
        remote_app, remote_unit, relation = self.setup_relation()
        self.harness.update_relation_data(
            relation.id, remote_app, {"ca_certificate": "some ca certificate"}
        )

        ca_certificate = self.harness.charm.interface.get_ca_certificate(relation)
        assert ca_certificate == "some ca certificate"
