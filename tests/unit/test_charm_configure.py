#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile
from datetime import timedelta
from unittest.mock import MagicMock, patch

import hcl
import ops.testing as testing
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    SecretsBackend,
)
from charms.vault_k8s.v0.vault_kv import KVRequest
from ops.pebble import Layer

from tests.unit.certificates import (
    generate_example_provider_certificate,
)
from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class MockRelation:
    def __init__(self, id: int):
        self.id = id


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_socket_fqdn.return_value = "myhostname"
            self.mock_autounseal_requires_get_details.return_value = None
            model_name = "whatever"
            vault_raft_mount = testing.Mount(
                location="/vault/raft",
                source=temp_dir,
            )
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-raft": vault_raft_mount,
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
                model=testing.Model(name=model_name),
            )

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()

            with open("tests/unit/config.hcl", "r") as f:
                expected_config = f.read()
            actual_content_hcl = hcl.loads(actual_config)
            expected_content_hcl = hcl.loads(expected_config)
            assert actual_content_hcl == expected_content_hcl

    def test_given_leader_when_configure_then_pebble_layer_is_planned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
            )

            state_out = self.ctx.run(self.ctx.on.pebble_ready(container), state_in)
            assert list(state_out.containers)[0].layers == {
                "vault": Layer(
                    {
                        "summary": "vault layer",
                        "description": "pebble config layer for vault",
                        "services": {
                            "vault": {
                                "summary": "vault",
                                "startup": "enabled",
                                "override": "replace",
                                "command": "vault server -config=/vault/config/vault.hcl",
                            }
                        },
                    }
                )
            }

    # PKI

    def test_given_certificate_available_when_configure_then_pki_secrets_engine_is_configured(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "get_intermediate_ca.return_value": "",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation = testing.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
            )
            approle_secret = testing.Secret(
                label="vault-approle-auth-details",
                tracked_content={"role-id": "role id", "secret-id": "secret id"},
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation],
                config={
                    "common_name": "myhostname.com",
                },
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation.id,
                validity=timedelta(hours=24),
            )
            self.mock_pki_requirer_get_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_pki_manager.configure.assert_called_once()

    # Test Auto unseal

    def test_given_autounseal_details_available_when_configure_then_transit_stanza_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_name = "my key"
            approle_id = "my approle id"
            approle_secret_id = "my approle secret id"
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "get_intermediate_ca.return_value": "",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                },
            )
            self.mock_vault_autounseal_manager.configure_mock(
                **{
                    "create_credentials.return_value": (key_name, approle_id, approle_secret_id),
                }
            )
            self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
                "1.2.3.4",
                "charm-autounseal",
                "key name",
                "role id",
                "secret id",
                "ca cert",
            )
            self.mock_vault_autounseal_requirer_manager.get_provider_vault_token.return_value = (
                "some token"
            )
            self.mock_tls.configure_mock(
                **{
                    "pull_tls_file_from_workload.return_value": "my ca",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
                "1.2.3.4", "charm-autounseal", "key name", "role id", "secret id", "ca cert"
            )
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            vault_autounseal_relation = testing.Relation(
                endpoint="vault-autounseal-provides",
                interface="vault-autounseal",
                remote_app_name="vault-autounseal-requirer",
            )
            self.mock_get_binding.return_value = MockBinding(
                bind_address="myhostname",
                ingress_address="myhostname",
            )
            relation = MockRelation(id=vault_autounseal_relation.id)
            self.mock_autounseal_provides_get_relations_without_credentials.return_value = [
                relation
            ]
            approle_secret = testing.Secret(
                label="vault-approle-auth-details",
                tracked_content={"role-id": "role id", "secret-id": "secret id"},
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, vault_autounseal_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()
            actual_config_hcl = hcl.loads(actual_config)
            assert actual_config_hcl["seal"]["transit"]["address"] == "1.2.3.4"
            assert actual_config_hcl["seal"]["transit"]["mount_path"] == "charm-autounseal"
            assert actual_config_hcl["seal"]["transit"]["token"] == "some token"
            assert actual_config_hcl["seal"]["transit"]["key_name"] == "key name"
            self.mock_vault.authenticate.assert_called_with(AppRole("role id", "secret id"))

    # Test KV

    def test_given_kv_request_when_configure_then_kv_relation_data_is_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "generate_role_secret_id.return_value": "kv role secret id",
                    "create_or_update_approle.return_value": "kv role id",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            kv_relation = testing.Relation(
                endpoint="vault-kv",
                interface="vault-kv",
                remote_app_name="vault-kv",
                remote_app_data={
                    "mount_suffix": "remote-suffix",
                },
                remote_units_data={
                    0: {
                        "nonce": "123123",
                        "egress_subnet": "2.2.2.0/24",
                    },
                },
            )
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            approle_secret = testing.Secret(
                label="vault-approle-auth-details",
                tracked_content={"role-id": "role id", "secret-id": "secret id"},
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                relations=[peer_relation, kv_relation],
                secrets=[approle_secret],
            )
            self.mock_kv_provides_get_credentials.return_value = {}

            state_out = self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_vault.enable_secrets_engine.assert_any_call(
                SecretsBackend.KV_V2, "charm-vault-kv-remote-suffix"
            )
            self.mock_kv_provides_set_kv_data.assert_called()
            assert state_out.get_secret(label="kv-creds-vault-kv-0").tracked_content == {
                "role-id": "kv role id",
                "role-secret-id": "kv role secret id",
            }

    @patch("charm.VaultKvProvides.get_kv_requests")
    def test_given_related_kv_client_unit_egress_is_updated_when_configure_then_secret_content_is_updated(
        self, mock_get_kv_requests: MagicMock
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            nonce = "123123"
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "generate_role_secret_id.return_value": "new kv role secret id",
                    "create_or_update_approle.return_value": "kv role id",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None

            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
            )
            kv_relation = testing.Relation(
                endpoint="vault-kv",
                interface="vault-kv",
                remote_app_name="vault-kv",
                remote_app_data={
                    "mount_suffix": "remote-suffix",
                },
                remote_units_data={
                    0: {
                        "nonce": nonce,
                        "egress_subnet": "2.2.2.0/24",
                    },
                },
            )
            vault_config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            self.mock_vault.read_role_secret.return_value = {"cidr_list": ["2.2.2.0/24"]}
            approle_secret = testing.Secret(
                label="vault-approle-auth-details",
                tracked_content={"role-id": "role id", "secret-id": "secret id"},
            )
            kv_secret = testing.Secret(
                label="kv-creds-vault-kv-remote-0",
                tracked_content={
                    "role-id": "kv role id",
                    "role-secret-id": "initial kv role secret id",
                },
                owner="app",
            )
            state_in = testing.State(
                containers=[container],
                leader=True,
                relations=[peer_relation, kv_relation],
                secrets=[approle_secret, kv_secret],
            )
            self.mock_kv_provides_get_credentials.return_value = {nonce: kv_secret.id}
            mock_get_kv_requests.return_value = [
                KVRequest(
                    relation=kv_relation,  # type: ignore
                    app_name="vault-kv-remote",
                    unit_name="vault-kv-remote/0",
                    mount_suffix="suffix",
                    egress_subnets=["2.2.2.0/24"],
                    nonce=nonce,
                )
            ]

            state_out = self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            assert state_out.get_secret(label="kv-creds-vault-kv-remote-0").latest_content == {
                "role-id": "kv role id",
                "role-secret-id": "new kv role secret id",
            }
