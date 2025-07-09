#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from typing import Any

import ops.testing as testing
import pytest
from ops.charm import ActionEvent, CharmBase
from vault.vault_autounseal import (
    VaultAutounsealDetailsReadyEvent,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)


class VaultAutounsealProviderCharm(CharmBase):
    def __init__(self, *args: Any):
        super().__init__(*args)
        self.interface = VaultAutounsealProvides(self, "vault-autounseal-provides")
        self.framework.observe(
            self.on.set_autounseal_data_action, self._on_set_autounseal_data_action
        )
        self.framework.observe(
            self.on.get_relations_without_credentials_action,
            self._on_get_relations_without_credentials_action,
        )

    def _on_set_autounseal_data_action(self, event: ActionEvent):
        ca_certificate = event.params.get("ca-certificate")
        relation_id = event.params.get("relation-id")
        vault_address = event.params.get("vault-address")
        mount_path = event.params.get("mount-path")
        key_name = event.params.get("key-name")
        approle_role_id = event.params.get("approle-role-id")
        approle_secret_id = event.params.get("approle-secret-id")
        assert ca_certificate
        assert relation_id
        assert vault_address
        assert mount_path
        assert key_name
        assert approle_role_id
        assert approle_secret_id

        relation = self.model.get_relation("vault-autounseal-provides", int(relation_id))
        assert relation

        self.interface.set_autounseal_data(
            ca_certificate=ca_certificate,
            relation=relation,
            vault_address=vault_address,
            mount_path=mount_path,
            key_name=key_name,
            approle_role_id=approle_role_id,
            approle_secret_id=approle_secret_id,
        )

    def _on_get_relations_without_credentials_action(self, event: ActionEvent):
        relations = self.interface.get_relations_without_credentials()
        event.set_results(results={"relations": [relation.id for relation in relations]})


class TestVaultAutounsealProvides:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultAutounsealProviderCharm,
            meta={
                "name": "vault-autounseal-provider",
                "provides": {"vault-autounseal-provides": {"interface": "vault-autounseal"}},
            },
            actions={
                "set-autounseal-data": {
                    "description": "Set the autounseal data",
                    "params": {
                        "ca-certificate": {
                            "type": "string",
                            "description": "The CA certificate",
                        },
                        "relation-id": {
                            "type": "string",
                            "description": "The relation id",
                        },
                        "vault-address": {
                            "type": "string",
                            "description": "The Vault address",
                        },
                        "mount-path": {
                            "type": "string",
                            "description": "The mount path",
                        },
                        "key-name": {
                            "type": "string",
                            "description": "The key name",
                        },
                        "approle-role-id": {
                            "type": "string",
                            "description": "The approle role id",
                        },
                        "approle-secret-id": {
                            "type": "string",
                            "description": "The approle secret id",
                        },
                    },
                },
                "get-relations-without-credentials": {
                    "description": "Get any relations which do not have credentials",
                },
            },
        )

    def test_given_unit_is_leader_when_set_autounseal_data_then_relation_data_is_updated(
        self,
    ):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            leader=True,
        )

        state_out = self.ctx.run(
            self.ctx.on.action(
                "set-autounseal-data",
                params={
                    "ca-certificate": "my ca certificate",
                    "relation-id": str(vault_autounseal_relation.id),
                    "vault-address": "https://vault.example.com",
                    "mount-path": "charm-autounseal",
                    "key-name": "some key name",
                    "approle-role-id": "some approle id",
                    "approle-secret-id": "some approle secret id",
                },
            ),
            state_in,
        )

        relation_data = state_out.get_relation(vault_autounseal_relation.id).local_app_data

        expected_relation_data = {
            "ca_certificate": "my ca certificate",
            "address": "https://vault.example.com",
            "mount_path": "charm-autounseal",
            "key_name": "some key name",
        }

        assert all(
            relation_data.get(key) == value for key, value in expected_relation_data.items()
        )

        credentials_secret_id = relation_data["credentials_secret_id"]

        assert state_out.get_secret(id=credentials_secret_id).tracked_content == {
            "role-id": "some approle id",
            "secret-id": "some approle secret id",
        }

    def test_given_unit_is_not_leader_when_set_autounseal_data_then_relation_data_not_updated(
        self,
    ):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            leader=False,
        )
        params = {
            "ca-certificate": "my ca certificate",
            "relation-id": str(vault_autounseal_relation.id),
            "vault-address": "https://vault.example.com",
            "mount-path": "charm-autounseal",
            "key-name": "some key name",
            "approle-role-id": "some approle id",
            "approle-secret-id": "some approle secret id",
        }
        state_out = self.ctx.run(
            self.ctx.on.action("set-autounseal-data", params=params), state_in
        )

        assert state_out.get_relation(vault_autounseal_relation.id).local_app_data == {}
        assert len(list(state_out.secrets)) == 0

    def test_given_no_request_when_get_relations_without_credentials_then_empty_list_is_returned(
        self,
    ):
        state_in = testing.State(
            relations=[],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-relations-without-credentials"), state_in)
        assert self.ctx.action_results
        assert self.ctx.action_results["relations"] == []

    def test_given_1_outstanding_request_when_get_relations_without_credentials_then_request_is_returned(
        self,
    ):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
            local_app_data={"address": "https://vault.example.com"},
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-relations-without-credentials"), state_in)
        assert self.ctx.action_results
        assert self.ctx.action_results["relations"] == [vault_autounseal_relation.id]

    def test_given_1_outstanding_and_1_satisfied_request_when_get_relations_without_credentials_then_outstanding_request_is_returned(
        self,
    ):
        vault_autounseal_relation_1_credentials_secret = testing.Secret(
            tracked_content={"role-id": "some role id", "secret-id": "some secret id"},
            owner="app",
        )
        vault_autounseal_relation_1 = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
            local_app_data={
                "credentials_secret_id": str(vault_autounseal_relation_1_credentials_secret.id)
            },
        )
        vault_autounseal_relation_2 = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation_1, vault_autounseal_relation_2],
            secrets=[vault_autounseal_relation_1_credentials_secret],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-relations-without-credentials"), state_in)
        assert self.ctx.action_results
        assert self.ctx.action_results["relations"] == [vault_autounseal_relation_2.id]

    def test_given_satisfied_request_when_get_relations_without_credentials_then_request_is_not_returned(
        self,
    ):
        vault_autounseal_relation_credentials_secret = testing.Secret(
            tracked_content={"role-id": "some role id", "secret-id": "some secret id"},
            owner="app",
        )
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
            local_app_data={
                "credentials_secret_id": str(vault_autounseal_relation_credentials_secret.id)
            },
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            secrets=[vault_autounseal_relation_credentials_secret],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-relations-without-credentials"), state_in)
        assert self.ctx.action_results
        assert self.ctx.action_results["relations"] == []

    def test_given_2_requests_when_get_relations_without_credentials_then_requests_are_returned(
        self,
    ):
        vault_autounseal_relation_1 = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        vault_autounseal_relation_2 = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation_1, vault_autounseal_relation_2],
            leader=True,
        )
        self.ctx.run(self.ctx.on.action("get-relations-without-credentials"), state_in)
        assert self.ctx.action_results
        assert set(self.ctx.action_results["relations"]) == {
            vault_autounseal_relation_1.id,
            vault_autounseal_relation_2.id,
        }


class VaultAutounsealRequirerCharm(CharmBase):
    def __init__(self, *args: Any):
        super().__init__(*args)
        self.interface = VaultAutounsealRequires(self, "vault-autounseal-requires")
        self.framework.observe(self.on.get_details_action, self._on_get_details_action)

    def _on_get_details_action(self, event: ActionEvent):
        details = self.interface.get_details()
        if not details:
            event.fail("No details available")
            return
        event.set_results(
            results={
                "details": {
                    "address": details.address,
                    "mount-path": details.mount_path,
                    "key-name": details.key_name,
                    "role-id": details.role_id,
                    "secret-id": details.secret_id,
                    "ca-certificate": details.ca_certificate,
                }
            }
        )


class TestVaultAutounsealRequires:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultAutounsealRequirerCharm,
            meta={
                "name": "vault-autounseal-requirer",
                "provides": {"vault-autounseal-requires": {"interface": "vault-autounseal"}},
            },
            actions={
                "get-details": {
                    "description": "Get the details",
                },
            },
        )

    def test_given_unit_joined_when_relation_changed_then_vault_auto_unseal_details_ready_event_is_fired(
        self,
    ):
        vault_autounseal_credentials_secret = testing.Secret(
            tracked_content={"role-id": "some role id", "secret-id": "some secret id"},
        )

        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-requires",
            interface="vault-autounseal",
            remote_app_data={
                "address": "https://vault.example.com",
                "mount_path": "charm-autounseal",
                "key_name": "some key name",
                "credentials_secret_id": str(vault_autounseal_credentials_secret.id),
                "ca_certificate": "some ca certificate",
            },
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            secrets=[vault_autounseal_credentials_secret],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_autounseal_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], VaultAutounsealDetailsReadyEvent)
        assert self.ctx.emitted_events[1].address == "https://vault.example.com"
        assert self.ctx.emitted_events[1].mount_path == "charm-autounseal"
        assert self.ctx.emitted_events[1].key_name == "some key name"
        assert self.ctx.emitted_events[1].role_id == "some role id"
        assert self.ctx.emitted_events[1].secret_id == "some secret id"
        assert self.ctx.emitted_events[1].ca_certificate == "some ca certificate"

    def test_given_unit_joined_when_data_missing_then_vault_auto_unseal_details_ready_event_not_fired(
        self,
    ):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-requires",
            interface="vault-autounseal",
            remote_app_data={
                "address": "https://vault.example.com",
                "mount_path": "charm-autounseal",
                "key_name": "some key name",
                # "credentials_secret_id": Missing!
                "ca_certificate": "some ca certificate",
            },
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            leader=True,
        )

        self.ctx.run(self.ctx.on.relation_changed(vault_autounseal_relation), state_in)
        assert len(self.ctx.emitted_events) == 1

    def test_given_all_details_present_when_get_details_then_details_are_returned(self):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-requires",
            interface="vault-autounseal",
            remote_app_data={
                "address": "https://vault.example.com",
                "mount_path": "charm-autounseal",
                "key_name": "some key name",
                "credentials_secret_id": "0",
                "ca_certificate": "some ca certificate",
            },
        )
        vault_autounseal_credentials_secret = testing.Secret(
            id="0",
            tracked_content={"role-id": "some role id", "secret-id": "some secret id"},
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            secrets=[vault_autounseal_credentials_secret],
            leader=True,
        )

        self.ctx.run(self.ctx.on.action("get-details"), state_in)

        assert self.ctx.action_results
        assert self.ctx.action_results["details"] == {
            "address": "https://vault.example.com",
            "mount-path": "charm-autounseal",
            "key-name": "some key name",
            "role-id": "some role id",
            "ca-certificate": "some ca certificate",
            "secret-id": "some secret id",
        }

    def test_given_no_details_when_get_details_then_none_is_returned(self):
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-requires",
            interface="vault-autounseal",
        )
        state_in = testing.State(
            relations=[vault_autounseal_relation],
            leader=True,
        )
        with pytest.raises(testing.ActionFailed):
            self.ctx.run(self.ctx.on.action("get-details"), state_in)
