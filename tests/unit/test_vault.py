#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, call, patch

import requests

from vault import Vault


class TestVault(unittest.TestCase):
    @patch("hvac.api.system_backend.Init.is_initialized")
    def test_given_vault_not_initialized_when_is_ready_then_return_false(
        self, patch_is_initialized
    ):
        patch_is_initialized.return_value = False

        vault = Vault(url="http://whatever-url")

        self.assertFalse(vault.is_ready())

    @patch("hvac.api.system_backend.seal.Seal.is_sealed")
    @patch("hvac.api.system_backend.Init.is_initialized")
    def test_given_vault_is_sealed_when_is_ready_then_return_false(
        self, patch_is_initialized, patch_is_sealed
    ):
        patch_is_initialized.return_value = True
        patch_is_sealed.return_value = True

        vault = Vault(url="http://whatever-url")

        self.assertFalse(vault.is_ready())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    @patch("hvac.api.system_backend.seal.Seal.is_sealed")
    @patch("hvac.api.system_backend.init.Init.is_initialized")
    def test_given_vault_health_returns_40x_when_is_ready_then_return_false(
        self, patch_is_initialized, patch_is_sealed, patch_read_health_status
    ):
        patch_is_initialized.return_value = True
        patch_is_sealed.return_value = False
        health_status_response = requests.Response()
        health_status_response.status_code = 404
        patch_read_health_status.return_value = health_status_response

        vault = Vault(url="http://whatever-url")

        self.assertFalse(vault.is_ready())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    @patch("hvac.api.system_backend.seal.Seal.is_sealed")
    @patch("hvac.api.system_backend.init.Init.is_initialized")
    def test_given_vault_health_returns_200_when_is_ready_then_return_true(
        self, patch_is_initialized, patch_is_sealed, patch_read_health_status
    ):
        patch_is_initialized.return_value = True
        patch_is_sealed.return_value = False
        health_status_response = requests.Response()
        health_status_response.status_code = 200
        patch_read_health_status.return_value = health_status_response

        vault = Vault(url="http://whatever-url")

        self.assertTrue(vault.is_ready())

    @patch("hvac.api.system_backend.init.Init.initialize")
    def test_given_shares_and_threshold_when_initialize_then_root_token_and_unseal_key_returned(
        self, patch_initialize
    ):
        root_token = "whatever root token"
        unseal_keys = ["key 1", "key 2", "key 3"]
        vault = Vault(url="http://whatever-url")
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
        vault = Vault(url="http://whatever-url")

        vault.unseal(unseal_keys=unseal_keys)

        patch_submit_unsealed_key.assert_has_calls(
            [call(unseal_key) for unseal_key in unseal_keys]
        )

    @patch("vault.Vault.is_ready")
    def test_given_is_ready_when_wait_to_be_ready_then_returns(self, patch_is_ready):
        patch_is_ready.return_value = True

        vault = Vault(url="http://whatever-url")

        vault.wait_to_be_ready(timeout=1)

    @patch("vault.Vault.is_ready")
    @patch("vault.sleep", new=Mock)
    def test_given_is_not_ready_when_wait_to_be_ready_then_timeout_error(self, patch_is_ready):
        patch_is_ready.return_value = False
        vault = Vault(url="http://whatever-url")

        with self.assertRaises(TimeoutError):
            vault.wait_to_be_ready(timeout=1)

    @patch("vault.Vault.is_api_available")
    def test_given_api_available_when_wait_for_api_available_then_returns(
        self, patch_is_api_available
    ):
        patch_is_api_available.return_value = True
        vault = Vault(url="http://whatever-url")

        vault.wait_for_api_available(timeout=1)

    @patch("vault.sleep", new=Mock)
    @patch("vault.Vault.is_api_available")
    def test_given_api_not_available_when_wait_for_api_available_then_timeouterror(
        self,
        patch_is_api_available,
    ):
        patch_is_api_available.return_value = False
        vault = Vault(url="http://whatever-url")

        with self.assertRaises(TimeoutError):
            vault.wait_for_api_available(timeout=1)

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_connection_error_when_is_api_available_then_return_false(
        self, patch_health_status
    ):
        patch_health_status.side_effect = requests.exceptions.ConnectionError()
        vault = Vault(url="http://whatever-url")

        self.assertFalse(vault.is_api_available())

    @patch("hvac.api.system_backend.health.Health.read_health_status")
    def test_given_api_returns_when_is_api_available_then_return_true(self, patch_health_status):
        patch_health_status.return_value = requests.Response()
        vault = Vault(url="http://whatever-url")

        self.assertTrue(vault.is_api_available())
