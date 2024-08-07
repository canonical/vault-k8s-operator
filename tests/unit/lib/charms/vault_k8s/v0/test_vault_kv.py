#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import textwrap
import unittest
from unittest.mock import patch

from charms.vault_k8s.v0.vault_kv import (
    KVRequest,
    NewVaultKvClientAttachedEvent,
    VaultKvConnectedEvent,
    VaultKvGoneAwayEvent,
    VaultKvProvides,
    VaultKvReadyEvent,
    VaultKvRequires,
    get_egress_subnets_list_from_relation_data,
)
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
        self.interface = VaultKvProvides(self, "vault-kv")
        self.framework.observe(
            self.interface.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
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
        self.interface = VaultKvRequires(
            self,
            relation_name="vault-kv",
            mount_suffix="dummy",
        )
        self.framework.observe(self.interface.on.connected, self._on_connected)
        self.framework.observe(self.interface.on.ready, self._on_ready)
        self.framework.observe(self.interface.on.gone_away, self._on_gone_away)

    def _on_connected(self, event: VaultKvConnectedEvent):
        pass

    def _on_ready(self, event: VaultKvReadyEvent):
        pass

    def _on_gone_away(self, event: VaultKvGoneAwayEvent):
        pass


class TestVaultKvProvides(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultKvProviderCharm, meta=VaultKvProviderCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, remote_app: str = "vault-kv-requires", leader: bool = True) -> tuple:
        """Set up a relation between the charm and a remote app with 1 unit."""
        remote_unit = remote_app + "/0"
        rel_name = "vault-kv"
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        return remote_app, remote_unit, relation, rel_id

    @patch("test_vault_kv.VaultKvProviderCharm._on_new_vault_kv_client_attached")
    def test_given_unit_joined_when_all_data_present_then_new_client_attached_fired(
        self, _on_new_vault_kv_client_attached
    ):
        remote_app, remote_unit, _, rel_id = self.setup_relation()
        suffix = "dummy"
        self.harness.update_relation_data(rel_id, remote_app, {"mount_suffix": suffix})
        self.harness.update_relation_data(
            rel_id,
            remote_unit,
            key_values={"nonce": "abcd", "egress_subnet": "10.0.0.1/32"},
        )
        args, _ = _on_new_vault_kv_client_attached.call_args
        event = args[0]

        assert isinstance(event, NewVaultKvClientAttachedEvent)
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

    def test_given_no_request_when_get_outstanding_kv_requests_then_empty_list_is_returned(self):
        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 0

    def test_given_1_outstanding_request_when_get_outstanding_kv_requests_then_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce = "abcd"
        egress_subnets = ["10.0.0.1/32"]
        remote_app, remote_unit, _, rel_id = self.setup_relation()
        self.harness.update_relation_data(
            rel_id,
            remote_unit,
            key_values={"nonce": nonce, "egress_subnet": ",".join(egress_subnets)},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=remote_app,
            key_values={"mount_suffix": suffix},
        )

        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 1
        assert kv_requests[0] == KVRequest(
            relation_id=rel_id,
            app_name=remote_app,
            unit_name=remote_unit,
            mount_suffix=suffix,
            egress_subnets=egress_subnets,
            nonce=nonce,
        )

    def test_given_1_outstanding_and_1_satisfied_request_when_get_outstanding_kv_requests_then_outstanding_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce_1 = "abcd"
        nonce_2 = "efgh"
        egress_subnets = ["10.0.0.1/32"]
        remote_app, remote_unit_1, _, rel_id = self.setup_relation()
        remote_unit_2 = remote_app + "/1"
        self.harness.add_relation_unit(
            rel_id,
            remote_unit_2,
        )
        self.harness.update_relation_data(
            rel_id,
            remote_unit_1,
            key_values={"nonce": nonce_1, "egress_subnet": ",".join(egress_subnets)},
        )
        self.harness.update_relation_data(
            rel_id,
            remote_unit_2,
            key_values={"nonce": nonce_2, "egress_subnet": ",".join(egress_subnets)},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=remote_app,
            key_values={"mount_suffix": suffix},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"credentials": json.dumps({nonce_1: "whatever secret id"})},
        )

        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 1
        assert kv_requests[0] == KVRequest(
            relation_id=rel_id,
            app_name=remote_app,
            unit_name=remote_unit_2,
            mount_suffix=suffix,
            egress_subnets=egress_subnets,
            nonce=nonce_2,
        )

    def test_given_2_vault_kv_relations_when_get_outstanding_kv_requests_then_outstanding_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce_1 = "abcd"
        nonce_2 = "efgh"
        egress_subnets_1 = ["10.0.0.1/32", "10.0.1.1/32"]
        egress_subnets_2 = ["10.0.0.2/32"]
        remote_app_1, remote_unit_1, _, rel_id_1 = self.setup_relation()
        remote_app_2, remote_unit_2, _, rel_id_2 = self.setup_relation(
            remote_app="vault-kv-requires-b"
        )
        self.harness.update_relation_data(
            rel_id_1,
            remote_unit_1,
            key_values={"nonce": nonce_1, "egress_subnet": ",".join(egress_subnets_1)},
        )
        self.harness.update_relation_data(
            rel_id_2,
            remote_unit_2,
            key_values={"nonce": nonce_2, "egress_subnet": ",".join(egress_subnets_2)},
        )
        self.harness.update_relation_data(
            relation_id=rel_id_1,
            app_or_unit=remote_app_1,
            key_values={"mount_suffix": suffix + "a"},
        )
        self.harness.update_relation_data(
            relation_id=rel_id_2,
            app_or_unit=remote_app_2,
            key_values={"mount_suffix": suffix + "b"},
        )
        self.harness.update_relation_data(
            relation_id=rel_id_1,
            app_or_unit=self.harness.charm.app.name,
            key_values={"credentials": json.dumps({nonce_1: "whatever secret id"})},
        )

        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 1
        assert kv_requests[0] == KVRequest(
            relation_id=rel_id_2,
            app_name=remote_app_2,
            unit_name=remote_unit_2,
            mount_suffix=suffix + "b",
            egress_subnets=egress_subnets_2,
            nonce=nonce_2,
        )

    def test_given_satisfied_request_when_get_outstanding_kv_requests_then_request_is_not_returned(
        self,
    ):
        nonce = "abcd"
        remote_app, remote_unit, _, rel_id = self.setup_relation()
        self.harness.update_relation_data(
            rel_id,
            remote_unit,
            key_values={"nonce": nonce, "egress_subnet": "10.0.0.1/32"},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=remote_app,
            key_values={"mount_suffix": "dummy"},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={"credentials": json.dumps({nonce: "whatever secret id"})},
        )

        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 0

    def test_given_no_request_when_get_kv_requests_then_empty_list_is_returned(self):
        kv_requests = self.harness.charm.interface.get_outstanding_kv_requests()

        assert len(kv_requests) == 0

    def test_given_2_requests_when_get_kv_requests_then_requests_are_returned(self):
        suffix = "dummy"
        nonce1 = "abcd"
        nonce2 = "efgh"
        egress_subnets = ["10.0.0.1/32"]
        remote_app, remote_unit_1, _, rel_id = self.setup_relation()
        remote_unit_2 = remote_app + "/1"
        self.harness.add_relation_unit(
            rel_id,
            remote_unit_2,
        )
        self.harness.update_relation_data(
            rel_id,
            remote_unit_1,
            key_values={"nonce": nonce1, "egress_subnet": ",".join(egress_subnets)},
        )
        self.harness.update_relation_data(
            rel_id,
            remote_unit_2,
            key_values={"nonce": nonce2, "egress_subnet": ",".join(egress_subnets)},
        )
        self.harness.update_relation_data(
            relation_id=rel_id,
            app_or_unit=remote_app,
            key_values={"mount_suffix": suffix},
        )

        kv_requests = self.harness.charm.interface.get_kv_requests()

        assert len(kv_requests) == 2
        expected_kv_request_1 = KVRequest(
            relation_id=rel_id,
            app_name=remote_app,
            unit_name=remote_unit_1,
            mount_suffix=suffix,
            egress_subnets=egress_subnets,
            nonce=nonce1,
        )
        expected_kv_request_2 = KVRequest(
            relation_id=rel_id,
            app_name=remote_app,
            unit_name=remote_unit_2,
            mount_suffix=suffix,
            egress_subnets=egress_subnets,
            nonce=nonce2,
        )
        assert expected_kv_request_1 in kv_requests
        assert expected_kv_request_2 in kv_requests


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
        self.harness.charm.interface.request_credentials(relation, "10.20.20.1/32", "abcd")
        return remote_app, remote_unit, relation, rel_id

    @patch("test_vault_kv.VaultKvRequirerCharm._on_connected")
    def test_given_unit_leader_when_unit_joined_then_connected_event_fired_and_all_relation_data_is_updated(  # noqa: E501
        self, _on_connected
    ):
        rel_id = self.setup_relation()[-1]

        args, _ = _on_connected.call_args
        event = args[0]

        app_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.app.name)
        assert isinstance(event, VaultKvConnectedEvent)
        assert app_relation_data["mount_suffix"] == self.harness.charm.interface.mount_suffix

    @patch("test_vault_kv.VaultKvRequirerCharm._on_connected")
    def test_given_unit_leader_when_config_changed_then_connected_event_fired(self, _on_connected):
        self.setup_relation()
        self.harness.charm.on.config_changed.emit()

        self.assertEqual(_on_connected.call_count, 2)

    @patch("test_vault_kv.VaultKvRequirerCharm._on_connected")
    def test_given_unit_joined_is_not_leader_when_relation_joined_then_connected_is_fired_and_mount_suffix_is_not_updated(  # noqa: E501
        self, _on_connected
    ):
        rel_id = self.setup_relation(leader=False)[-1]

        args, _ = _on_connected.call_args
        event = args[0]

        app_relation_data = self.harness.get_relation_data(rel_id, self.harness.charm.app.name)
        assert isinstance(event, VaultKvConnectedEvent)
        assert "mount_suffix" not in app_relation_data

    @patch("test_vault_kv.VaultKvRequirerCharm._on_gone_away")
    def test_given_all_units_departed_when_relation_broken_then_gone_away_event_fired(
        self, _on_gone_away
    ):
        rel_id = self.setup_relation()[-1]
        self.harness.remove_relation(rel_id)
        args, _ = _on_gone_away.call_args
        event = args[0]

        assert isinstance(event, VaultKvGoneAwayEvent)

    @patch("test_vault_kv.VaultKvRequirerCharm._on_ready")
    def test_given_relation_changed_when_all_data_present_then_ready_event_fired(self, _on_ready):
        remote_app, _, _, rel_id = self.setup_relation()
        self.harness.update_relation_data(
            rel_id,
            remote_app,
            {
                "vault_url": "https://vault.example.com",
                "ca_certificate": "ca certificate data",
                "mount": "charm-vault-kv-requires-dummy",
                "egress_subnet": "1.1.1.1",
                "credentials": json.dumps({"abcd": "dummy"}),
            },
        )

        args, _ = _on_ready.call_args
        event = args[0]

        assert isinstance(event, VaultKvReadyEvent)

    @patch("test_vault_kv.VaultKvRequirerCharm._on_ready")
    def test_given_relation_changed_when_data_missing_then_ready_event_never_fired(
        self, _on_ready
    ):
        self.setup_relation()
        _on_ready.assert_not_called()

    def test_given_egress_subnets_in_relation_databag_when_get_egress_subnets_list_from_relation_data_then_list_is_returned(  # noqa: E501
        self,
    ):
        relation_datbage_dict = {
            "nonce": "abcd",
            "egress_subnet": "10.0.0.1/32, 10.0.1.1/32,10.0.2.1/32",
        }
        assert sorted(get_egress_subnets_list_from_relation_data(relation_datbage_dict)) == sorted(
            ["10.0.0.1/32", "10.0.1.1/32", "10.0.2.1/32"]
        )
