#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import call, patch

from certificates import generate_csr, generate_private_key

from vault import Vault


class TestVault(unittest.TestCase):
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
    def test_given_default_role_parameters_when_write_roles_then_two_roles_are_created(
        self, patch_write
    ):
        vault = Vault(url="http://whatever-url")

        vault.write_roles()

        calls = [
            call(
                "charm-pki-local/roles/local",
                server_flag=True,
                allow_any_name=True,
                allowed_domains=None,
                allow_bare_domains=False,
                allow_subdomains=False,
                allow_glob_domains=True,
                enforce_hostnames=False,
                max_ttl="87598h",
                client_flag=True,
            ),
            call(
                "charm-pki-local/roles/local-client",
                server_flag=False,
                allow_any_name=True,
                allowed_domains=None,
                allow_bare_domains=False,
                allow_subdomains=False,
                allow_glob_domains=True,
                enforce_hostnames=False,
                max_ttl="87598h",
                client_flag=True,
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
    def test_given_backend_not_mounted_when_enable_secrets_engine_then_secrets_engine_is_enabled(
        self,
        patch_enable_secrets_engine,
        patch_list_mounted_secrets_engine,
    ):
        patch_list_mounted_secrets_engine.return_value = dict()
        vault = Vault(url="http://whatever-url")

        vault.enable_secrets_engine()

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
