#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, patch

import requests
from charm import AUTOUNSEAL_POLICY_PATH
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    Vault,
    VaultClientError,
)
from hvac.exceptions import InvalidPath

TEST_PATH = "./tests/unit/lib/charms/vault_k8s/v0"


class TestVault(unittest.TestCase):
    def test_given_token_as_auth_details_when_authenticate_then_token_is_set(self):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.authenticate(Token("some token"))

        assert vault._client.token == "some token"

    @patch("hvac.api.auth_methods.approle.AppRole.login")
    def test_given_approle_as_auth_details_when_authenticate_then_approle_login_is_called(
        self, patch_approle_login
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.authenticate(AppRole(role_id="some role id", secret_id="some secret id"))

        patch_approle_login.assert_called_with(
            role_id="some role id", secret_id="some secret id", use_token=True
        )

    @patch("hvac.api.auth_methods.token.Token.lookup_self")
    def test_given_token_data_when_get_token_data_lookup_self_called(self, patch_lookup):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.get_token_data()
        patch_lookup.assert_called()

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_connection_error_when_is_api_available_then_return_false(
        self, patch_health_status
    ):
        patch_health_status.side_effect = requests.exceptions.ConnectionError()
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        self.assertFalse(vault.is_api_available())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_api_returns_when_is_api_available_then_return_true(self, patch_health_status):
        patch_health_status.return_value = requests.Response()
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        self.assertTrue(vault.is_api_available())

    @patch("hvac.api.system_backend.raft.Raft.read_raft_config")
    def test_given_node_in_peer_list_when_is_node_in_raft_peers_then_returns_true(
        self, patch_health_status
    ):
        node_id = "whatever node id"
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_health_status.return_value = {
            "data": {"config": {"servers": [{"node_id": node_id}]}}
        }

        self.assertTrue(vault.is_node_in_raft_peers(node_id=node_id))

    @patch("hvac.api.system_backend.raft.Raft.read_raft_config")
    def test_given_node_not_in_peer_list_when_is_node_in_raft_peers_then_returns_false(
        self, patch_health_status
    ):
        node_id = "whatever node id"
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_health_status.return_value = {
            "data": {"config": {"servers": [{"node_id": "not our node"}]}}
        }

        self.assertFalse(vault.is_node_in_raft_peers(node_id=node_id))

    @patch("hvac.api.system_backend.raft.Raft.read_raft_config")
    def test_given_1_node_in_raft_cluster_when_get_num_raft_peers_then_returns_1(
        self, patch_health_status
    ):
        patch_health_status.return_value = {
            "data": {
                "config": {
                    "servers": [
                        {"node_id": "node 1"},
                        {"node_id": "node 2"},
                        {"node_id": "node 3"},
                    ]
                }
            }
        }

        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        vault.get_num_raft_peers()

        self.assertEqual(3, vault.get_num_raft_peers())

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    def test_given_approle_not_in_auth_methods_when_enable_approle_auth_then_approle_is_added_to_auth_methods(  # noqa: E501
        self, patch_enable_auth_method
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        vault.enable_approle_auth_method()

        patch_enable_auth_method.assert_called_once()

    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_audit_device_is_not_yet_enabled_when_enable_audit_device_then_device_is_enabled(
        self,
        patch_enable_audit_device,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
        patch_enable_audit_device.assert_called_once_with(
            device_type="file", options={"file_path": "stdout"}
        )

    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_audit_device_is_enabled_when_enable_audit_device_then_nothing_happens(
        self,
        patch_enable_audit_device,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
        patch_enable_audit_device.assert_called_once_with(
            device_type="file", options={"file_path": "stdout"}
        )

    @patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
    def test_given_policy_with_mount_when_configure_policy_then_policy_is_formatted_properly(
        self, patch_create_policy
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.configure_policy(
            "test-policy", policy_path=f"{TEST_PATH}/kv_with_mount.hcl", mount="example"
        )
        with open(f"{TEST_PATH}/kv_mounted.hcl", "r") as f:
            policy = f.read()
            patch_create_policy.assert_called_with(
                name="test-policy",
                policy=policy,
            )

    @patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
    def test_given_policy_without_mount_when_configure_policy_then_policy_created_correctly(
        self, patch_create_policy
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.configure_policy("test-policy", policy_path=f"{TEST_PATH}/kv_mounted.hcl")
        with open(f"{TEST_PATH}/kv_mounted.hcl", "r") as f:
            policy = f.read()
            patch_create_policy.assert_called_with(
                name="test-policy",
                policy=policy,
            )

    @patch("hvac.api.auth_methods.approle.AppRole.read_role_id")
    @patch("hvac.api.auth_methods.approle.AppRole.create_or_update_approle")
    def test_given_approle_with_valid_params_when_configure_approle_then_approle_created(
        self, patch_create_approle, patch_read_role_id
    ):
        patch_read_role_id.return_value = {"data": {"role_id": "1234"}}
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        assert "1234" == vault.configure_approle(
            "test-approle",
            policies=["root", "default"],
            cidrs=["192.168.1.0/24"],
            token_max_ttl="1h",
            token_ttl="1h",
        )

        patch_create_approle.assert_called_with(
            "test-approle",
            bind_secret_id="true",
            token_ttl="1h",
            token_max_ttl="1h",
            token_policies=["root", "default"],
            token_bound_cidrs=["192.168.1.0/24"],
            token_period=None,
        )
        patch_read_role_id.assert_called_once()

    @patch("hvac.api.system_backend.mount.Mount.enable_secrets_engine")
    def test_given_secrets_engine_with_valid_params_when_enable_secrets_engine_then_secrets_engine_enabled(
        self, patch_enable_secrets_engine
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.enable_secrets_engine(SecretsBackend.KV_V2, "some/path")

        patch_enable_secrets_engine.assert_called_with(
            backend_type=SecretsBackend.KV_V2.value,
            description=f"Charm created '{SecretsBackend.KV_V2.value}' backend",
            path="some/path",
        )

    @patch("hvac.api.system_backend.mount.Mount.disable_secrets_engine")
    def test_when_disable_secrets_engine_then_secrets_engine_disabled(
        self, mock_disable_secrets_engine: MagicMock
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.disable_secrets_engine("some/path")

        mock_disable_secrets_engine.assert_called_with("some/path")

    @patch("hvac.api.system_backend.policy.Policy.delete_policy")
    @patch("hvac.api.auth_methods.approle.AppRole.delete_role")
    def test_when_destroy_autounseal_credentials_then_approle_and_policy_are_deleted(
        self, mock_delete_role: MagicMock, mock_delete_policy: MagicMock
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        relation_id = 1
        mount = "example"
        vault.destroy_autounseal_credentials(relation_id, mount)

        mock_delete_role.assert_called_with(f"charm-autounseal-{relation_id}")
        mock_delete_policy.assert_called_with(f"charm-autounseal-{relation_id}")

    @patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
    @patch("hvac.api.auth_methods.approle.AppRole.generate_secret_id")
    @patch("hvac.api.auth_methods.approle.AppRole.read_role_id")
    @patch("hvac.api.auth_methods.approle.AppRole.create_or_update_approle")
    @patch("hvac.api.secrets_engines.transit.Transit.create_key")
    def test_when_create_autounseal_credentials_then_key_and_approle_and_policy_are_created(
        self,
        mock_create_key: MagicMock,
        mock_create_approle: MagicMock,
        mock_read_role_id: MagicMock,
        mock_generate_secret_id: MagicMock,
        mock_create_policy: MagicMock,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        relation_id = 1
        mount = "example_mount"
        vault.create_autounseal_credentials(relation_id, mount, AUTOUNSEAL_POLICY_PATH)

        with open(f"{TEST_PATH}/autounseal_policy_formatted.hcl", "r") as f:
            expected_policy = f.read()
        mock_create_key.assert_called_with(mount_point=mount, name=str(relation_id))
        mock_create_policy.assert_called_with(
            name=f"charm-autounseal-{relation_id}", policy=expected_policy
        )
        mock_create_approle.assert_called_with(
            f"charm-autounseal-{relation_id}",
            bind_secret_id="true",
            token_ttl=None,
            token_max_ttl=None,
            token_policies=[f"charm-autounseal-{relation_id}"],
            token_bound_cidrs=None,
            token_period="60s",
        )

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_health_status_returns_200_when_is_active_then_return_true(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 200
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertTrue(vault.is_active_or_standby())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_health_status_returns_standby_when_is_active_then_return_false(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 429
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertTrue(vault.is_active_or_standby())
        self.assertFalse(vault.is_active())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_health_status_returns_5xx_when_is_active_then_return_false(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 501
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.is_active_or_standby())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_connection_error_when_is_active_then_return_false(self, patch_health_status):
        patch_health_status.side_effect = requests.exceptions.ConnectionError()
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.is_active_or_standby())

    @patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
    def test_given_no_pki_issuers_when_make_latest_pki_issuer_default_then_vault_client_error_is_raised(
        self,
        patch_read_pki_issuers,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_read_pki_issuers.side_effect = InvalidPath()
        with self.assertRaises(VaultClientError):
            vault.make_latest_pki_issuer_default(mount="test")

    @patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
    @patch("hvac.Client.write_data")
    @patch("hvac.Client.read")
    def test_given_existing_pki_issuers_when_make_latest_pki_issuer_default_then_config_written_to_path(
        self,
        patch_read,
        patch_write,
        patch_read_pki_issuers,
    ):
        patch_read.return_value = {
            "data": {"default_follows_latest_issuer": False, "default": "whatever issuer"}
        }
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_read_pki_issuers.return_value = {"data": {"keys": ["issuer"]}}
        mount = "test"
        vault.make_latest_pki_issuer_default(mount=mount)
        patch_write.assert_called_with(
            path=f"{mount}/config/issuers",
            data={
                "default_follows_latest_issuer": True,
                "default": "issuer",
            },
        )

    @patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
    @patch("hvac.Client.write_data")
    @patch("hvac.Client.read")
    def test_given_issuers_config_already_updated_when_make_latest_pki_issuer_default_then_config_not_written(
        self,
        patch_read,
        patch_write,
        patch_read_pki_issuers,
    ):
        patch_read.return_value = {
            "data": {"default_follows_latest_issuer": True, "default": "whatever issuer"}
        }
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_read_pki_issuers.return_value = {"data": {"keys": ["issuer"]}}
        mount = "test"
        vault.make_latest_pki_issuer_default(mount=mount)
        patch_write.assert_not_called()
