#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, call, patch

import requests

from vault import Vault


def infinite_time_values(start=0, step=2):
    """Generator that returns an infinite sequence of time values.

    Args:
        start: Initial time value.
        step: Time step between values.
    """
    current_time = start
    while True:
        yield current_time
        current_time += step


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

    @patch("hvac.api.system_backend.audit.Audit.list_enabled_audit_devices")
    @patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
    def test_given_audit_device_already_enabled_when_enable_audit_device_then_method_not_called(
        self,
        patch_enable_audit_device,
        patch_list_enabled_audit_devices,
    ):
        patch_list_enabled_audit_devices.return_value = {
            "data": {
                "file/": {"options": {"file_path": "stdout"}, "path": "file/", "type": "file"}
            }
        }
        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        vault.enable_audit_device(device_type="file", path="stdout")
        patch_enable_audit_device.assert_not_called()

    @patch("vault.Vault.is_sealed")
    @patch("time.sleep", new=Mock)
    @patch("time.time")
    def test_given_vault_stays_sealed_when_wait_for_unseal_then_timeout_error_is_raised(
        self,
        patch_time,
        patch_is_sealed,
    ):
        time_values = infinite_time_values()
        patch_time.side_effect = lambda: next(time_values)

        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_is_sealed.return_value = True

        with self.assertRaises(TimeoutError):
            vault.wait_for_unseal(timeout=30)

    @patch("vault.Vault.is_sealed")
    @patch("time.sleep", new=Mock)
    @patch("time.time")
    def test_given_vault_is_unsealed_when_wait_for_unseal_then_returns(
        self,
        patch_time,
        patch_is_sealed,
    ):
        time_values = infinite_time_values()
        patch_time.side_effect = lambda: next(time_values)

        vault = Vault(url="http://whatever-url", ca_cert_path="whatever path")
        patch_is_sealed.return_value = False
        vault.wait_for_unseal(timeout=30)
