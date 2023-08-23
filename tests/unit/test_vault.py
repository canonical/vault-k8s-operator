#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, call, patch

import requests
from certificates import generate_csr, generate_private_key

from vault import Vault


class TestVault(unittest.TestCase):
    @patch("vault.Vault.get_approle_auth_data")
    @patch("vault.Vault.create_local_charm_access_approle")
    @patch("vault.Vault.create_local_charm_policy")
    @patch("vault.Vault.enable_approle_auth")
    @patch("vault.Vault.write_charm_pki_role")
    @patch("vault.Vault.generate_root_certificate")
    @patch("vault.Vault.enable_pki_secrets_engine")
    @patch("vault.Vault.wait_to_be_ready")
    def test_given_when_bootstrap_then(
        self,
        patch_wait_to_be_ready,
        patch_enable_pki_secrets_engine,
        patch_generate_root_certificate,
        patch_write_charm_pki_role,
        patch_enable_approle_auth,
        patch_create_local_charm_policy,
        patch_create_local_charm_access_approle,
        patch_get_approle_auth_data,
    ):
        approle_role_id = "approle role id"
        approle_secret_id = "approle secret id"
        patch_get_approle_auth_data.return_value = approle_role_id, approle_secret_id
        vault = Vault(url="http://whatever-url")

        returned_approle_role_id, returned_approle_secret_id = vault.bootstrap()

        patch_wait_to_be_ready.assert_called_once()
        patch_enable_pki_secrets_engine.assert_called_once()
        patch_generate_root_certificate.assert_called_once()
        patch_write_charm_pki_role.assert_called_once()
        patch_enable_approle_auth.assert_called_once()
        patch_create_local_charm_policy.assert_called_once()
        patch_create_local_charm_access_approle.assert_called_once()
        patch_get_approle_auth_data.assert_called_once()

        self.assertEqual(returned_approle_role_id, approle_role_id)
        self.assertEqual(returned_approle_secret_id, approle_secret_id)

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

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    @patch("hvac.api.system_backend.auth.Auth.list_auth_methods")
    def test_given_approle_not_in_auth_methods_when_enable_approle_auth_then_approle_is_added_to_auth_methods(  # noqa: E501
        self, patch_list_auth_methods, patch_enable_auth_method
    ):
        patch_list_auth_methods.return_value = {}
        vault = Vault(url="http://whatever-url")

        vault.enable_approle_auth()

        patch_enable_auth_method.assert_called_with("approle")

    @patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
    @patch("hvac.api.system_backend.auth.Auth.list_auth_methods")
    def test_given_approle_in_auth_methods_when_enable_approle_auth_then_approle_is_not_added_to_auth_methods(  # noqa: E501
        self, patch_list_auth_methods, patch_enable_auth_method
    ):
        patch_list_auth_methods.return_value = {"approle/": "whatever"}
        vault = Vault(url="http://whatever-url")

        vault.enable_approle_auth()

        patch_enable_auth_method.assert_not_called()

    @patch("hvac.Client.write")
    def test_given_default_role_parameters_when_write_charm_pki_role_then_role_is_created(
        self, patch_write
    ):
        vault = Vault(url="http://whatever-url")

        vault.write_charm_pki_role()

        calls = [
            call(
                "charm-pki-local/roles/local",
                allow_any_name=True,
                allowed_domains=None,
                allow_bare_domains=False,
                allow_subdomains=False,
                allow_glob_domains=True,
                enforce_hostnames=False,
                max_ttl="87598h",
            ),
        ]
        patch_write.assert_has_calls(calls=calls)

    @patch("hvac.Client.write")
    def test_given_certificate_returned_by_vault_when_generate_root_certificate_then_certificate_is_returned(  # noqa: E501
        self, patch_write
    ):
        certificate = "whatever certificate"
        patch_write.return_value = {"data": {"certificate": certificate}}
        vault = Vault(url="http://whatever-url")

        returned_value = vault.generate_root_certificate()

        self.assertEqual(certificate, returned_value)

    @patch("hvac.api.system_backend.mount.Mount.list_mounted_secrets_engines")
    @patch("hvac.api.system_backend.mount.Mount.enable_secrets_engine")
    def test_given_backend_not_mounted_when_enable_pki_secrets_engine_then_secrets_engine_is_enabled(  # noqa: E501
        self,
        patch_enable_secrets_engine,
        patch_list_mounted_secrets_engine,
    ):
        patch_list_mounted_secrets_engine.return_value = dict()
        vault = Vault(url="http://whatever-url")

        vault.enable_pki_secrets_engine()

        patch_enable_secrets_engine.assert_called_with(
            backend_type="pki",
            description="Charm created PKI backend",
            path="charm-pki-local",
            config={"default_lease_ttl": "8759h", "max_lease_ttl": "87600h"},
        )

    @patch("hvac.Client.read")
    @patch("hvac.Client.write")
    def test_given_csr_when_issue_certificate_then_vault_issue_api_is_called(
        self, patch_write, patch_read
    ):
        common_name = "whatever common name"
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, subject=common_name)
        patch_read.return_value = "whatever"
        patch_write.return_value = {
            "data": {"certificate": "whatever certificate", "key": "whatever key"}
        }
        vault = Vault(url="http://whatever-url")

        vault.issue_certificate(certificate_signing_request=csr.decode())

        patch_write.assert_called_with(
            path="charm-pki-local/sign/local",
            common_name=common_name,
            csr=csr.decode(),
            format="pem",
        )

    @patch("hvac.Client.read")
    @patch("hvac.Client.write")
    def test_given_certificate_created_when_issue_certificate_then_certificate_is_returned(
        self, patch_write, patch_read
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key=private_key, subject="whatever")
        patch_read.return_value = "whatever"
        certificate_data = {"certificate": "whatever certificate", "key": "whatever key"}
        patch_write.return_value = {"data": certificate_data}
        vault = Vault(url="http://whatever-url")

        certificate = vault.issue_certificate(certificate_signing_request=csr.decode())

        self.assertEqual(certificate_data, certificate)
