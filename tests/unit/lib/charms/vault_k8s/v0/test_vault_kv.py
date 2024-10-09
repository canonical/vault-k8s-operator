#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from dataclasses import asdict

import ops.testing as testing
import pytest
from charms.vault_k8s.v0.vault_kv import (
    NewVaultKvClientAttachedEvent,
    VaultKvClientDetachedEvent,
    VaultKvConnectedEvent,
    VaultKvGoneAwayEvent,
    VaultKvProvides,
    VaultKvReadyEvent,
    VaultKvRequires,
    get_egress_subnets_list_from_relation_data,
)
from ops.charm import ActionEvent, CharmBase

VAULT_KV_RELATION_NAME = "vault-kv"


class VaultKvProviderCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultKvProvides(self, "vault-kv")
        self.framework.observe(
            self.interface.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )
        self.framework.observe(
            self.interface.on.vault_kv_client_detached, self._on_vault_kv_client_detached
        )
        self.framework.observe(
            self.on.set_vault_url_action,
            self._on_set_vault_url_action,
        )
        self.framework.observe(self.on.set_mount_action, self._on_set_mount_action)
        self.framework.observe(
            self.on.set_unit_credentials_action, self._on_set_unit_credentials_action
        )
        self.framework.observe(
            self.on.get_outstanding_kv_requests_action,
            self._on_get_outstanding_kv_requests_action,
        )
        self.framework.observe(
            self.on.get_kv_requests_action,
            self._on_get_kv_requests_action,
        )

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
        pass

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        pass

    def _on_set_vault_url_action(self, event: ActionEvent):
        url = event.params.get("url", "")
        relation_id = event.params.get("relation-id", "")
        relation = self.model.get_relation(
            relation_name=VAULT_KV_RELATION_NAME,
            relation_id=int(relation_id),
        )
        assert relation
        self.interface.set_vault_url(relation, url)

    def _on_set_mount_action(self, event: ActionEvent):
        mount = event.params.get("mount", "")
        relation_id = event.params.get("relation-id", "")
        relation = self.model.get_relation(
            relation_name=VAULT_KV_RELATION_NAME,
            relation_id=int(relation_id),
        )
        assert relation
        self.interface.set_mount(relation, mount)

    def _on_set_unit_credentials_action(self, event: ActionEvent):
        nonce = event.params.get("nonce", "")
        secret_id = event.params.get("secret-id", "")
        relation_id = event.params.get("relation-id", "")
        relation = self.model.get_relation(
            relation_name=VAULT_KV_RELATION_NAME,
            relation_id=int(relation_id),
        )
        assert relation
        secret = self.model.get_secret(id=secret_id)
        self.interface.set_unit_credentials(relation=relation, nonce=nonce, secret=secret)

    def _on_get_outstanding_kv_requests_action(self, event: ActionEvent):
        kv_requests = self.interface.get_outstanding_kv_requests()
        event.set_results(
            {"kv-requests": json.dumps([asdict(kv_request) for kv_request in kv_requests])}
        )

    def _on_get_kv_requests_action(self, event: ActionEvent):
        kv_requests = self.interface.get_kv_requests()
        event.set_results(
            {"kv-requests": json.dumps([asdict(kv_request) for kv_request in kv_requests])}
        )


class VaultKvRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultKvRequires(
            self,
            relation_name=VAULT_KV_RELATION_NAME,
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
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultKvProviderCharm,
            meta={
                "name": "vault-kv-provider",
                "provides": {"vault-kv": {"interface": "vault-kv"}},
            },
            actions={
                "set-vault-url": {
                    "description": "Set the vault url",
                    "params": {
                        "url": {
                            "type": "string",
                            "description": "The url of the vault server",
                        },
                        "relation-id": {
                            "type": "string",
                            "description": "The relation id",
                        },
                    },
                },
                "set-mount": {
                    "description": "Set the mount",
                    "params": {
                        "mount": {
                            "type": "string",
                            "description": "The mount",
                        },
                        "relation-id": {
                            "type": "string",
                            "description": "The relation id",
                        },
                    },
                },
                "set-unit-credentials": {
                    "description": "Set the unit credentials",
                    "params": {
                        "nonce": {
                            "type": "string",
                            "description": "The nonce",
                        },
                        "secret-id": {
                            "type": "string",
                            "description": "The secret id",
                        },
                        "relation-id": {
                            "type": "string",
                            "description": "The relation id",
                        },
                    },
                },
                "get-outstanding-kv-requests": {
                    "description": "Get the outstanding kv requests",
                },
                "get-kv-requests": {
                    "description": "Get the kv requests",
                },
            },
        )

    def test_given_unit_joined_when_all_data_present_then_new_client_attached_fired(
        self,
    ):
        suffix = "dummy"
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": "abcd", "egress_subnet": "10.0.0.1/32"}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], NewVaultKvClientAttachedEvent)
        assert self.ctx.emitted_events[1].egress_subnets == ["10.0.0.1/32"]
        assert self.ctx.emitted_events[1].mount_suffix == suffix
        assert self.ctx.emitted_events[1].nonce == "abcd"

    def test_given_unit_joined_when_missing_data_then_new_client_attached_is_never_fired(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 1

    def test_given_unit_is_leader_when_setting_vault_url_then_relation_data_is_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        vault_url = "https://vault.example.com"
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-vault-url",
                params={
                    "url": vault_url,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )

        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {
            "vault_url": vault_url
        }

    def test_given_unit_is_not_leader_when_setting_vault_url_then_relation_data_is_not_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        vault_url = "https://vault.example.com"
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=False,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-vault-url",
                params={
                    "url": vault_url,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )

        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {}

    def test_given_unit_is_leader_when_setting_mount_then_relation_data_is_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        mount = "charm-vault-kv-requires-dummy"
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-mount",
                params={
                    "mount": mount,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )

        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {"mount": mount}

    def test_given_unit_is_not_leader_when_setting_mount_then_relation_data_is_not_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        mount = "charm-vault-kv-requires-dummy"
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=False,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-mount",
                params={
                    "mount": mount,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )
        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {}

    def test_given_unit_is_leader_when_setting_credentials_then_relation_data_is_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        secret = testing.Secret(tracked_content={})
        nonce = "abcd"
        state_in = testing.State(
            relations=[vault_kv_relation],
            secrets=[secret],
            leader=True,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-unit-credentials",
                params={
                    "nonce": nonce,
                    "secret-id": secret.id,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )

        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {
            "credentials": json.dumps({nonce: f"{secret.id}"})
        }

    def test_given_unit_is_not_leader_when_setting_credentials_then_relation_data_is_not_updated(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        secret = testing.Secret(tracked_content={})
        nonce = "abcd"
        state_in = testing.State(
            relations=[vault_kv_relation],
            secrets=[secret],
            leader=False,
        )
        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-unit-credentials",
                params={
                    "nonce": nonce,
                    "secret-id": secret.id,
                    "relation-id": str(vault_kv_relation.id),
                },
            ),
            state_in,
        )

        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {}

    def test_given_no_request_when_get_outstanding_kv_requests_then_empty_list_is_returned(self):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.action("get-outstanding-kv-requests"), state_in)

        assert self.ctx.action_results == {"kv-requests": "[]"}

    def test_given_1_outstanding_request_when_get_outstanding_kv_requests_then_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce = "abcd"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": nonce, "egress_subnet": ",".join(egress_subnets)}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-outstanding-kv-requests"), state_in)

        assert self.ctx.action_results == {
            "kv-requests": json.dumps(
                [
                    {
                        "relation_id": vault_kv_relation.id,
                        "app_name": vault_kv_relation.remote_app_name,
                        "unit_name": f"{vault_kv_relation.remote_app_name}/0",
                        "mount_suffix": suffix,
                        "egress_subnets": egress_subnets,
                        "nonce": nonce,
                    }
                ]
            )
        }

    def test_given_1_outstanding_and_1_satisfied_request_when_get_outstanding_kv_requests_then_outstanding_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce_1 = "abcd"
        nonce_2 = "efgh"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={
                0: {"nonce": nonce_1, "egress_subnet": ",".join(egress_subnets)},
                1: {"nonce": nonce_2, "egress_subnet": ",".join(egress_subnets)},
            },
            local_app_data={"credentials": json.dumps({nonce_1: "whatever secret id"})},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-outstanding-kv-requests"), state_in)

        assert self.ctx.action_results == {
            "kv-requests": json.dumps(
                [
                    {
                        "relation_id": vault_kv_relation.id,
                        "app_name": vault_kv_relation.remote_app_name,
                        "unit_name": f"{vault_kv_relation.remote_app_name}/1",
                        "mount_suffix": suffix,
                        "egress_subnets": egress_subnets,
                        "nonce": nonce_2,
                    }
                ]
            )
        }

    def test_given_2_vault_kv_relations_when_get_outstanding_kv_requests_then_outstanding_request_is_returned(
        self,
    ):
        suffix = "dummy"
        nonce_1 = "abcd"
        nonce_2 = "efgh"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation_1 = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": nonce_1, "egress_subnet": ",".join(egress_subnets)}},
        )
        vault_kv_relation_2 = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": nonce_2, "egress_subnet": ",".join(egress_subnets)}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation_1, vault_kv_relation_2],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-outstanding-kv-requests"), state_in)

        assert self.ctx.action_results == {
            "kv-requests": json.dumps(
                [
                    {
                        "relation_id": vault_kv_relation_1.id,
                        "app_name": vault_kv_relation_1.remote_app_name,
                        "unit_name": f"{vault_kv_relation_1.remote_app_name}/0",
                        "mount_suffix": suffix,
                        "egress_subnets": egress_subnets,
                        "nonce": nonce_1,
                    },
                    {
                        "relation_id": vault_kv_relation_2.id,
                        "app_name": vault_kv_relation_2.remote_app_name,
                        "unit_name": f"{vault_kv_relation_2.remote_app_name}/0",
                        "mount_suffix": suffix,
                        "egress_subnets": egress_subnets,
                        "nonce": nonce_2,
                    },
                ]
            )
        }

    def test_given_satisfied_request_when_get_outstanding_kv_requests_then_request_is_not_returned(
        self,
    ):
        suffix = "dummy"
        nonce = "abcd"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": nonce, "egress_subnet": ",".join(egress_subnets)}},
            local_app_data={"credentials": json.dumps({nonce: "whatever secret id"})},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-outstanding-kv-requests"), state_in)

        assert self.ctx.action_results == {"kv-requests": "[]"}

    def test_given_no_request_when_get_kv_requests_then_empty_list_is_returned(self):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_data={},
            remote_units_data={0: {}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-kv-requests"), state_in)

        assert self.ctx.action_results == {"kv-requests": "[]"}

    def test_given_2_requests_when_get_kv_requests_then_requests_are_returned(self):
        suffix = "dummy"
        nonce1 = "abcd"
        nonce2 = "efgh"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={
                0: {"nonce": nonce1, "egress_subnet": ",".join(egress_subnets)},
                1: {"nonce": nonce2, "egress_subnet": ",".join(egress_subnets)},
            },
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-kv-requests"), state_in)

        assert self.ctx.action_results
        assert {
            "relation_id": vault_kv_relation.id,
            "app_name": vault_kv_relation.remote_app_name,
            "unit_name": f"{vault_kv_relation.remote_app_name}/0",
            "mount_suffix": suffix,
            "egress_subnets": egress_subnets,
            "nonce": nonce1,
        } in json.loads(self.ctx.action_results["kv-requests"])
        assert {
            "relation_id": vault_kv_relation.id,
            "app_name": vault_kv_relation.remote_app_name,
            "unit_name": f"{vault_kv_relation.remote_app_name}/1",
            "mount_suffix": suffix,
            "egress_subnets": egress_subnets,
            "nonce": nonce2,
        } in json.loads(self.ctx.action_results["kv-requests"])

    def test_given_vault_kv_relation_when_relation_departed_then_vault_kv_client_detached_event_fired(
        self,
    ):
        suffix = "dummy"
        nonce = "abcd"
        egress_subnets = ["10.0.0.1/32"]
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-requirer",
            remote_app_data={"mount_suffix": suffix},
            remote_units_data={0: {"nonce": nonce, "egress_subnet": ",".join(egress_subnets)}},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_departed(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvClientDetachedEvent)
        assert self.ctx.emitted_events[1].unit_name == f"{vault_kv_relation.remote_app_name}/0"


class TestVaultKvRequires:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultKvRequirerCharm,
            meta={
                "name": "vault-kv-requirer",
                "requires": {"vault-kv": {"interface": "vault-kv"}},
            },
        )

    def test_given_unit_leader_when_unit_joined_then_connected_event_fired_and_all_relation_data_is_updated(  # noqa: E501
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.relation_joined(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvConnectedEvent)
        assert self.ctx.emitted_events[1].relation_id == vault_kv_relation.id
        assert self.ctx.emitted_events[1].relation_name == vault_kv_relation.endpoint
        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {
            "mount_suffix": "dummy"
        }

    def test_given_unit_leader_when_config_changed_then_connected_event_fired(self):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvConnectedEvent)
        assert self.ctx.emitted_events[1].relation_id == vault_kv_relation.id
        assert self.ctx.emitted_events[1].relation_name == vault_kv_relation.endpoint
        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {
            "mount_suffix": "dummy"
        }

    def test_given_unit_joined_is_not_leader_when_relation_joined_then_connected_is_fired_and_mount_suffix_is_not_updated(  # noqa: E501
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=False,
        )

        state_out = self.ctx.run(self.ctx.on.relation_joined(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvConnectedEvent)
        assert self.ctx.emitted_events[1].relation_id == vault_kv_relation.id
        assert self.ctx.emitted_events[1].relation_name == vault_kv_relation.endpoint
        assert state_out.get_relation(vault_kv_relation.id).local_app_data == {}

    def test_given_all_units_departed_when_relation_broken_then_gone_away_event_fired(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_broken(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvGoneAwayEvent)

    def test_given_relation_changed_when_all_data_present_then_ready_event_fired(self):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
            local_unit_data={
                "nonce": "abcd",
            },
            remote_app_data={
                "vault_url": "https://vault.example.com",
                "ca_certificate": "ca certificate data",
                "mount": "charm-vault-kv-requires-dummy",
                "egress_subnet": "1.1.1.1",
                "credentials": json.dumps({"abcd": "dummy"}),
            },
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultKvReadyEvent)
        assert self.ctx.emitted_events[1].relation_id == vault_kv_relation.id
        assert self.ctx.emitted_events[1].relation_name == vault_kv_relation.endpoint

    def test_given_relation_changed_when_data_missing_then_ready_event_never_fired(
        self,
    ):
        vault_kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv-provides",
            local_unit_data={
                "nonce": "abcd",
            },
            remote_app_data={},
        )
        state_in = testing.State(
            relations=[vault_kv_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_kv_relation), state_in)

        assert len(self.ctx.emitted_events) == 1

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
