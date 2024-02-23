#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import call, patch

import requests
from charms.vault_k8s.v0.vault_client import Vault
from tls import generate_ca, generate_private_key  # type: ignore[import-not-found]


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

    @patch("hvac.api.secrets_engines.pki.Pki.read_ca_certificate")
    def test_given_ca_common_name_matches_when_is_intermediate_ca_set_with_common_name_then_return_true(
        self, patch_read_ca_certificate
    ):
        common_name = "whatever.com"
        private_key = generate_private_key()
        ca_certificate = generate_ca(private_key=private_key, subject=common_name)
        patch_read_ca_certificate.return_value = ca_certificate
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        is_set = vault.is_intermediate_ca_set_with_common_name(
            mount="PKI_MOUNT", common_name=common_name
        )

        self.assertTrue(is_set)

    @patch("hvac.api.secrets_engines.pki.Pki.read_ca_certificate")
    def test_given_ca_common_name_does_not_match_when_is_intermediate_ca_set_with_common_name_then_return_false(  # noqa: E501
        self, patch_read_ca_certificate
    ):
        common_name = "whatever.com"
        private_key = generate_private_key()
        ca_certificate = generate_ca(private_key=private_key, subject="WRONG SUBJECT")
        patch_read_ca_certificate.return_value = ca_certificate
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")

        is_set = vault.is_intermediate_ca_set_with_common_name(
            mount="PKI_MOUNT", common_name=common_name
        )

        self.assertFalse(is_set)
