#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import call, patch

import requests
from charms.vault_k8s.v0.vault_client import AppRole, AuditDeviceType, SecretsBackend, Token, Vault

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

    @patch("hvac.api.system_backend.init.Init.initialize")
    def test_given_shares_and_threshold_when_initialize_then_root_token_and_unseal_key_returned(
        self, patch_initialize
    ):
        root_token = "whatever root token"
        unseal_keys = ["key 1", "key 2", "key 3"]
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_initialize.return_value = {"root_token": root_token, "keys": unseal_keys}

        returned_root_token, returned_unseal_keys = vault.initialize(
            secret_shares=5, secret_threshold=2
        )

        self.assertEqual(returned_root_token, root_token)
        self.assertEqual(returned_unseal_keys, unseal_keys)

    @patch("hvac.api.system_backend.seal.Seal.submit_unseal_key")
    def test_given_n_unseal_keys_when_unseal_then_unseal_called_n_times(
        self, patch_submit_unsealed_key
    ):
        n = 7  # arbitrary number
        unseal_keys = [f"unseal key #{i}" for i in range(n)]
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        vault.unseal(unseal_keys=unseal_keys)

        patch_submit_unsealed_key.assert_has_calls(
            [call(unseal_key) for unseal_key in unseal_keys]
        )

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

        patch_enable_auth_method.assert_called_with("approle")

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_audit_device_is_not_yet_enabled_when_enable_audit_device_then_device_is_enabled(
        self,
        patch_enable_audit_device,
        patch_list_enabled_audit_devices,
    ):
        patch_list_enabled_audit_devices.return_value = {"data": {}}
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
            "test-approle", ["root", "default"], ["192.168.1.0/24"]
        )

        patch_create_approle.assert_called_with(
            "test-approle",
            token_ttl="60s",
            token_max_ttl="60s",
            token_policies=["root", "default"],
            bind_secret_id="true",
            token_bound_cidrs=["192.168.1.0/24"],
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

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_health_status_returns_200_when_is_active_then_return_true(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 200
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertTrue(vault.is_active())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_health_status_returns_5xx_when_is_active_then_return_false(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 501
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.is_active())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_connection_error_when_is_active_then_return_false(self, patch_health_status):
        patch_health_status.side_effect = requests.exceptions.ConnectionError()
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.is_active())
