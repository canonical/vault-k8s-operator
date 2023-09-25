#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import textwrap
import unittest
from unittest.mock import patch

from charms.vault_k8s.v0 import vault_kv
from ops import testing
from ops.charm import CharmBase


class VaultKvProviderCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-kv-provider
        containers:
          vault:
            resource: vault-image
        provides:
          vault-kv:
            interface: vault-kv
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = vault_kv.VaultKvProvides(self, "vault-kv")
        self.framework.observe(
            self.interface.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )

    def _on_new_vault_kv_client_attached(self, event: vault_kv.NewVaultKvClientAttachedEvent):
        pass


class VaultKvRequirerCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-kv-requirer
        containers:
          my-app:
            resource: my-app-image
        requires:
          vault-kv:
            interface: vault-kv
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = vault_kv.VaultKvRequires(self, "vault-kv", "dummy", "abcd")
        self.framework.observe(self.interface.on.connected, self._on_connected)
        self.framework.observe(self.interface.on.ready, self._on_ready)
        self.framework.observe(self.interface.on.gone_away, self._on_gone_away)

    def _on_connected(self, event: vault_kv.VaultKvConnectedEvent):
        pass

    def _on_ready(self, event: vault_kv.VaultKvReadyEvent):
        pass

    def _on_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent):
        pass


class TestVaultKvProvides(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultKvProviderCharm, meta=VaultKvProviderCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, leader: bool = True) -> tuple:
        remote_app = "vault-kv-requires"
        remote_unit = remote_app + "/0"
        rel_name = "vault-kv"
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        self.harness.update_relation_data(
            rel_id,
            remote_unit,
            key_values={"nonce": "abcd", "egress_subnet": "10.0.0.1/32"},
        )
        return remote_app, remote_unit, relation, rel_id

    @patch("test_vault_kv.VaultKvProviderCharm._on_new_vault_kv_client_attached")
    def test_given_unit_joined_when_all_data_present_then_new_client_attached_fired(
        self, _on_new_vault_kv_client_attached
    ):
        remote_app, _, _, rel_id = self.setup_relation()

        suffix = "dummy"
        self.harness.update_relation_data(rel_id, remote_app, {"mount_suffix": suffix})
        args, _ = _on_new_vault_kv_client_attached.call_args
        event = args[0]

        assert isinstance(event, vault_kv.NewVaultKvClientAttachedEvent)
        assert args[0].mount_suffix == suffix

    @patch("test_vault_kv.VaultKvProviderCharm._on_new_vault_kv_client_attached")
    def test_given_unit_joined_when_missing_data_then_new_client_attached_is_never_fired(
        self, _on_new_vault_kv_client_attached
    ):
        self.setup_relation()
        _on_new_vault_kv_client_attached.assert_not_called()

    def test_given_unit_is_leader_when_setting_vault_url_then_relation_data_is_updated(
        self,
    ):
        _, _, relation, rel_id = self.setup_relation()
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert (
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)["vault_url"]
            == vault_url
        )

    def test_given_unit_is_not_leader_when_setting_vault_url_then_relation_data_is_not_updated(
        self,
    ):
        _, _, relation, rel_id = self.setup_relation(leader=False)
        vault_url = "https://vault.example.com"
        self.harness.charm.interface.set_vault_url(relation, vault_url)

        assert "vault_url" not in self.harness.get_relation_data(
            rel_id, self.harness.charm.app.name
        )

    def test_given_unit_is_leader_when_setting_mount_then_relation_data_is_updated(
        self,
    ):
        _, _, relation, rel_id = self.setup_relation()
        mount = "charm-vault-kv-requires-dummy"
        self.harness.charm.interface.set_mount(relation, mount)

        assert (
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)["mount"] == mount
        )

    def test_given_unit_is_not_leader_when_setting_mount_then_relation_data_is_not_updated(
        self,
    ):
        _, _, relation, rel_id = self.setup_relation(leader=False)
        mount = "charm-vault-kv-requires-dummy"
        self.harness.charm.interface.set_mount(relation, mount)

        assert "mount" not in self.harness.get_relation_data(rel_id, self.harness.charm.app.name)

    def test_given_unit_is_leader_when_setting_credentials_then_relation_data_is_updated(
        self,
    ):
        _, remote_unit, relation, rel_id = self.setup_relation()
        unit_name = remote_unit.replace("/", "-")
        secret = self.harness.charm.app.add_secret({"role-id": "111", "role-secret-id": "222"})
        self.harness.charm.interface.set_unit_credentials(relation, unit_name, secret)

        assert json.loads(
            self.harness.get_relation_data(rel_id, self.harness.charm.app.name)["credentials"]
        ) == {unit_name: secret.id}

    def test_given_unit_is_not_leader_when_setting_credentials_then_relation_data_is_not_updated(
        self,
    ):
        _, remote_unit, relation, rel_id = self.setup_relation(leader=False)
        unit_name = remote_unit.replace("/", "-")
        secret = self.harness.charm.app.add_secret({"role-id": "111", "role-secret-id": "222"})
        self.harness.charm.interface.set_unit_credentials(relation, unit_name, secret)

        assert "credentials" not in self.harness.get_relation_data(
            rel_id, self.harness.charm.app.name
        )

    def test_given_secret_is_missing_id_when_setting_credentials_then_relation_data_is_not_updated(
        self,
    ):
        """Secret._id is None when the secret has been looked up by label."""
        _, remote_unit, relation, rel_id = self.setup_relation()
        unit_name = remote_unit.replace("/", "-")
        secret = self.harness.charm.app.add_secret({"role-id": "111", "role-secret-id": "222"})
        secret._id = None
        self.harness.charm.interface.set_unit_credentials(relation, unit_name, secret)

        assert "credentials" not in self.harness.get_relation_data(
            rel_id, self.harness.charm.app.name
        )


class TestVaultKvRequires(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultKvRequirerCharm, meta=VaultKvRequirerCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, leader: bool = True) -> tuple:
        remote_app = "vault-kv-provides"
        remote_unit = remote_app + "/0"
        rel_name = "vault-kv"
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        self.harness.charm.interface.request_credentials(relation, "10.20.20.1/32")
        return remote_app, remote_unit, relation, rel_id

    @patch("test_vault_kv.VaultKvRequirerCharm._on_connected")
    def test_given_unit_leader_when_unit_joined_then_connected_event_fired_and_all_relation_data_is_updated(  # noqa: E501
        self, _on_connected
    ):
        rel_id = self.setup_relation()[-1]

        args, _ = _on_connected.call_args
        event = args[0]

        app_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.app.name)
        unit_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.unit.name)
        assert isinstance(event, vault_kv.VaultKvConnectedEvent)
        assert app_relation_data["mount_suffix"] == self.harness.charm.interface.mount_suffix
        assert unit_relation_data["nonce"] == self.harness.charm.interface.nonce

    @patch("test_vault_kv.VaultKvRequirerCharm._on_connected")
    def test_given_unit_joined_is_not_leader_when_relation_joined_then_connected_is_fired_and_mount_suffix_is_not_updated(  # noqa: E501
        self, _on_connected
    ):
        rel_id = self.setup_relation(leader=False)[-1]

        args, _ = _on_connected.call_args
        event = args[0]

        app_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.app.name)
        unit_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.unit.name)
        assert isinstance(event, vault_kv.VaultKvConnectedEvent)
        assert "mount_suffix" not in app_relation_data
        assert unit_relation_data["nonce"] == self.harness.charm.interface.nonce

    @patch("test_vault_kv.VaultKvRequirerCharm._on_gone_away")
    def test_given_all_units_departed_when_relation_broken_then_gone_away_event_fired(
        self, _on_gone_away
    ):
        rel_id = self.setup_relation()[-1]
        self.harness.remove_relation(rel_id)
        args, _ = _on_gone_away.call_args
        event = args[0]

        assert isinstance(event, vault_kv.VaultKvGoneAwayEvent)

    @patch("secrets.token_hex")
    @patch("test_vault_kv.VaultKvRequirerCharm._on_ready")
    def test_given_relation_changed_when_all_data_present_then_ready_event_fired(
        self, _on_ready, token_hex
    ):
        remote_app, _, _, rel_id = self.setup_relation()
        self.harness.update_relation_data(
            rel_id,
            remote_app,
            {
                "vault_url": "https://vault.example.com",
                "ca_certificate": "ca certificate data",
                "mount": "charm-vault-kv-requires-dummy",
                "credentials": json.dumps({self.harness.charm.interface.nonce: "dummy"}),
            },
        )

        args, _ = _on_ready.call_args
        event = args[0]

        assert isinstance(event, vault_kv.VaultKvReadyEvent)

    @patch("test_vault_kv.VaultKvRequirerCharm._on_ready")
    def test_given_relation_changed_when_data_missing_then_ready_event_never_fired(
        self, _on_ready
    ):
        self.setup_relation()
        _on_ready.assert_not_called()
