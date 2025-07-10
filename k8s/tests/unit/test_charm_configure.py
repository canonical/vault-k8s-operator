#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile
from datetime import timedelta
from pathlib import Path

import hcl
import ops.testing as testing
import pytest
from ops.pebble import Layer
from vault.vault_autounseal import AutounsealDetails
from vault.vault_client import (
    AppRole,
)

from certificate_helpers import (
    generate_example_provider_certificate,
)
from fixtures import MockBinding, VaultCharmFixtures


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
                    "pki_ca_common_name": "myhostname.com",
                },
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation.id,
                validity=timedelta(hours=24),
            )
            self.mock_get_requirer_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )
            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_pki_manager.configure.assert_called_once()

    @pytest.mark.parametrize(
        "config_key, config_value",
        [
            ("pki_allowed_domains", "This should have been a comma separated list"),
            ("pki_ca_sans_dns", "This should have been a comma separated list"),
        ],
    )
    def test_given_pki_config_is_invalid_when_configure_then_pki_secrets_engine_is_not_configured(
        self, config_key: str, config_value: str
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
                    "pki_ca_common_name": "myhostname.com",
                    config_key: config_value,
                },
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation.id,
                validity=timedelta(hours=24),
            )
            self.mock_get_requirer_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )
            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_pki_manager.configure.assert_not_called()

    # Test ACME

    def test_given_certificate_available_when_configure_then_acme_server_is_configured(
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
            acme_relation = testing.Relation(
                endpoint="tls-certificates-acme",
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
                relations=[peer_relation, acme_relation],
                config={
                    "acme_ca_common_name": "myhostname.com",
                },
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=acme_relation.id,
                validity=timedelta(hours=24),
            )
            self.mock_get_requirer_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_acme_manager.configure.assert_called_once()

    @pytest.mark.parametrize(
        "config_key, config_value",
        [
            ("acme_allowed_domains", "This should have been a comma separated list"),
            ("acme_ca_sans_dns", "This should have been a comma separated list"),
        ],
    )
    def test_given_acme_config_is_invalid_when_configure_then_acme_server_is_not_configured(
        self, config_key: str, config_value: str
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
            acme_relation = testing.Relation(
                endpoint="tls-certificates-acme",
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
                relations=[peer_relation, acme_relation],
                config={
                    "acme_ca_common_name": "myhostname.com",
                    config_key: config_value,
                },
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=acme_relation.id,
                validity=timedelta(hours=24),
            )
            self.mock_get_requirer_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )
            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            self.mock_acme_manager.configure.assert_not_called()

    # Test Auto unseal

    def test_given_autounseal_details_available_when_configure_then_transit_stanza_generated(
        self, tmp_path: Path
    ):
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
            },
        )
        self.mock_vault_autounseal_provider_manager.configure_mock(
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
            source=tmp_path,
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
        self.mock_autounseal_provides_get_relations_without_credentials.return_value = [relation]
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, vault_autounseal_relation],
            config={"pki_ca_common_name": "myhostname.com"},
        )

        self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

        with open(f"{tmp_path}/vault.hcl", "r") as f:
            actual_config = f.read()
        actual_config_hcl = hcl.loads(actual_config)
        assert actual_config_hcl["seal"]["transit"]["address"] == "1.2.3.4"
        assert actual_config_hcl["seal"]["transit"]["mount_path"] == "charm-autounseal"
        assert actual_config_hcl["seal"]["transit"]["key_name"] == "key name"
        self.mock_vault.authenticate.assert_called_with(AppRole("role id", "secret id"))

    def test_given_autounseal_details_available_when_configure_then_token_added_to_layer(
        self, tmp_path: Path
    ):
        self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
            address="http://fake.com",
            mount_path="fake-mount",
            key_name="fake-key",
            role_id="fake-role-id",
            secret_id="fake-secret-id",
            ca_certificate="fake-ca-cert",
        )
        self.mock_vault_autounseal_requirer_manager.get_provider_vault_token.return_value = (
            "some token"
        )

        vault_config_mount = testing.Mount(
            location="/vault/config",
            source=tmp_path,
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
                            "environment": {
                                "VAULT_TOKEN": "some token",
                            },
                        }
                    },
                }
            )
        }

    # Test KV

    def test_given_kv_request_when_configure_then_generate_credentials_for_requirer_is_called(
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

            self.mock_get_binding.return_value = MockBinding("vault", "vault")
            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            kwargs = self.mock_kv_manager.generate_credentials_for_requirer.call_args_list[
                0
            ].kwargs
            assert kwargs["relation"].id == kv_relation.id
            assert kwargs["app_name"] == "vault-kv"
            assert kwargs["unit_name"] == "vault-kv/0"
            assert kwargs["mount_suffix"] == "remote-suffix"
            assert kwargs["egress_subnets"] == ["2.2.2.0/24"]
            assert kwargs["nonce"] == "123123"
            assert kwargs["vault_url"] == "https://vault:8200"
