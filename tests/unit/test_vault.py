#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import call, mock_open, patch

import requests
from hvac.exceptions import InternalServerError  # type: ignore[import-untyped]

from vault import Vault, VaultClientError

EXCEPTIONS_TO_TEST = [requests.exceptions.ConnectionError(), InternalServerError()]


class TestVault(unittest.TestCase):
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
        )  # type: ignore[misc]

        self.assertEqual(returned_root_token, root_token)
        self.assertEqual(returned_unseal_keys, unseal_keys)

    @patch("hvac.api.system_backend.init.Init.initialize")
    def test_given_error_when_initialize_then_none_returned(self, patch_initialize):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_initialize.side_effect = exception
                self.assertIsNone(vault.initialize(secret_shares=5, secret_threshold=2))

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

    @patch("hvac.api.system_backend.seal.Seal.submit_unseal_key")
    def test_given_error_when_unseal_then_vault_client_error_is_raised(
        self, patch_submit_unsealed_key
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_submit_unsealed_key.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.unseal(unseal_keys=["whatever unseal key"])

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_error_when_is_api_available_then_return_false(self, patch_health_status):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_health_status.side_effect = exception
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
        self, patch_read_raft_config
    ):
        node_id = "whatever node id"
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_read_raft_config.return_value = {
            "data": {"config": {"servers": [{"node_id": "not our node"}]}}
        }

        self.assertFalse(vault.is_node_in_raft_peers(node_id=node_id))

    @patch("hvac.api.system_backend.raft.Raft.read_raft_config")
    def test_given_error_when_is_node_in_raft_peers_then_vault_client_error_is_raised(
        self, patch_read_raft_config
    ):
        node_id = "whatever node id"
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_read_raft_config.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.is_node_in_raft_peers(node_id=node_id)

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

    @patch("hvac.api.system_backend.raft.Raft.read_raft_config")
    def test_given_error_when_get_num_raft_peers_then_vault_client_error_is_raised(
        self, read_raft_config
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                read_raft_config.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.get_num_raft_peers()

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    @patch("hvac.api.system_backend.auth.Auth.list_auth_methods")
    def test_given_approle_not_in_auth_methods_when_enable_approle_auth_then_approle_is_added_to_auth_methods(  # noqa: E501
        self, patch_list_auth_methods, patch_enable_auth_method
    ):
        patch_list_auth_methods.return_value = {}
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        vault.enable_approle_auth()

        patch_enable_auth_method.assert_called_with("approle")

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    @patch("hvac.api.system_backend.auth.Auth.list_auth_methods")
    def test_given_approle_in_auth_methods_when_enable_approle_auth_then_approle_is_not_added_to_auth_methods(  # noqa: E501
        self, patch_list_auth_methods, patch_enable_auth_method
    ):
        patch_list_auth_methods.return_value = {"approle/": "whatever"}
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        vault.enable_approle_auth()

        patch_enable_auth_method.assert_not_called()

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    def test_given_error_when_enable_approle_auth_then_vault_client_error_is_raised(
        self,
        patch_enable_auth_method,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_enable_auth_method.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.enable_approle_auth()

    @patch("hvac.api.system_backend.mount.Mount.enable_secrets_engine")
    @patch("hvac.api.system_backend.mount.Mount.list_mounted_secrets_engines")
    def test_given_kv_mount_not_in_mounted_engines_when_configure_kv_mount_then_mount_is_enabled(
        self,
        patch_list_mounted_secrets_engines,
        patch_enable_secrets_engine,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_list_mounted_secrets_engines.return_value = {}
        path_name = "whatever_path_name"
        vault.configure_kv_mount(name=path_name)
        patch_enable_secrets_engine.assert_called_once_with(
            backend_type="kv-v2",
            description="Charm created KV backend",
            path=path_name,
        )

    @patch("hvac.api.system_backend.mount.Mount.list_mounted_secrets_engines")
    def test_given_error_when_configure_kv_mount_then_vault_client_error_is_raised(
        self,
        patch_list_mounted_secrets_engines,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_list_mounted_secrets_engines.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.configure_kv_mount(name="whatever path name")

    @patch("hvac.api.system_backend.mount.Mount.enable_secrets_engine")
    @patch("hvac.api.system_backend.mount.Mount.list_mounted_secrets_engines")
    def test_given_kv_mount_in_mounted_engines_when_configure_kv_mount_then_mount_is_not_enabled(
        self,
        patch_list_mounted_secrets_engines,
        patch_enable_secrets_engine,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        path_name = "whatever_path_name"
        patch_list_mounted_secrets_engines.return_value = {path_name + "/": "whatever"}
        vault.configure_kv_mount(name=path_name)
        patch_enable_secrets_engine.assert_not_called()

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_audit_device_is_not_yet_enabled_when_enable_audit_device_then_device_is_enabled(
        self,
        patch_enable_audit_device,
        patch_list_enabled_audit_devices,
    ):
        patch_list_enabled_audit_devices.return_value = {"data": {}}
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.enable_audit_device(device_type="file", path="stdout")
        patch_enable_audit_device.assert_called_once_with(
            device_type="file", options={"file_path": "stdout"}
        )

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_error_when_enable_audit_device_then_vault_client_error_is_raised(
        self,
        patch_enable_audit_device,
        patch_list_enabled_audit_devices,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_list_enabled_audit_devices.return_value = {"data": {}}
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_enable_audit_device.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.enable_audit_device(device_type="file", path="stdout")

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
    def test_given_health_status_returns_4xx_when_is_active_then_return_false(
        self, patch_health_status
    ):
        response = requests.Response()
        response.status_code = 429
        patch_health_status.return_value = response
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.is_active())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_error_when_is_active_then_return_false(self, patch_health_status):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_health_status.side_effect = exception
                self.assertFalse(vault.is_active())

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    def test_given_file_and_path_in_audit_device_list_when_audit_device_enabled_then_return_true(
        self, patch_list_enabled_audit_devices
    ):
        device_type = "file"
        path = "stdout"
        patch_list_enabled_audit_devices.return_value = {
            "data": {f"{device_type}/": {"options": {"file_path": path}}}
        }
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertTrue(vault.audit_device_enabled(device_type=device_type, path=path))

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    def test_given_file_not_in_audit_device_list_when_audit_device_enabled_then_return_false(
        self, patch_list_enabled_audit_devices
    ):
        device_type = "file"
        path = "stdout"
        patch_list_enabled_audit_devices.return_value = {"data": {}}
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.audit_device_enabled(device_type=device_type, path=path))

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    def test_given_wrong_path_in_audit_device_list_when_audit_device_enabled_then_return_false(
        self, patch_list_enabled_audit_devices
    ):
        device_type = "file"
        path = "stdout"
        patch_list_enabled_audit_devices.return_value = {
            "data": {f"{device_type}/": {"options": {"file_path": "WRONG PATH"}}}
        }
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        self.assertFalse(vault.audit_device_enabled(device_type=device_type, path=path))

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    def test_given_error_when_audit_device_enabled_then_vault_client_error_is_raised(
        self, patch_list_enabled_audit_devices
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_list_enabled_audit_devices.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.audit_device_enabled(device_type="whatever", path="whatever")

    @patch("hvac.api.system_backend.raft.Raft.remove_raft_node")
    def test_given_error_when_remove_raft_node_then_vault_client_error_is_raised(
        self, patch_remove_node
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_remove_node.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.remove_raft_node(node_id="whatever node id")

    @patch("builtins.open", new_callable=mock_open, read_data="mocked content")
    @patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
    def test_given_error_when_configure_kv_policy_then_vault_client_error_is_raised(
        self,
        patch_create_or_update_policy,
        _,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_create_or_update_policy.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.configure_kv_policy(policy="whatever policy", mount="whatever mount")

    @patch("hvac.api.system_backend.raft.Raft.take_raft_snapshot")
    def test_given_error_when_create_snapshot_then_vault_client_error_is_raised(
        self,
        patch_take_raft_snapshot,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_take_raft_snapshot.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.create_snapshot()

    @patch("hvac.api.system_backend.raft.Raft.force_restore_raft_snapshot")
    def test_given_error_when_restore_snapshot_then_vault_client_error_is_raised(
        self,
        patch_force_restore_raft_snapshot,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_force_restore_raft_snapshot.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.restore_snapshot(snapshot=b"whatever snapshot")

    @patch("hvac.api.auth_methods.approle.AppRole.create_or_update_approle")
    def test_given_error_when_configure_approle_then_vault_client_error_is_raised(
        self,
        patch_create_or_update_approle,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_create_or_update_approle.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.configure_approle(
                        name="whatever name", cidrs=["whatever cidr"], policies=["whatever policy"]
                    )

    @patch("hvac.api.auth_methods.approle.AppRole.read_secret_id")
    def test_given_error_when_read_role_secret_then_vault_client_error_is_raised(
        self,
        patch_read_secret_id,
    ):
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        for exception in EXCEPTIONS_TO_TEST:
            with self.subTest(exception=exception):
                patch_read_secret_id.side_effect = exception
                with self.assertRaises(VaultClientError):
                    vault.read_role_secret(name="whatever name", id="id")
