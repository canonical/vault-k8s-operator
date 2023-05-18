#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, PropertyMock, call, patch

from ops import testing
from ops.model import ActiveStatus, BlockedStatus

from charm import VaultCharm

testing.SIMULATE_CAN_CONNECT = True  # type: ignore[attr-defined]


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports, service_type: None,
    )
    def setUp(self):
        self.harness = testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("ops.model.Container.exec")
    @patch("charm.VaultCharm._bind_address", new_callable=PropertyMock)
    def test_given_pebble_plan_not_set_when_pebble_ready_then_service_is_created_in_vault_container(  # noqa: E501
        self, patch_bind_address, _
    ):
        patch_bind_address.return_value = "127.0.1.1"
        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        "VAULT_LOCAL_CONFIG": '{"backend": {"file": {"path": "/srv"}}, '
                        '"listener": {"tcp": {'
                        '"tls_disable": true, "address": "[::]:8200"}}, '
                        '"default_lease_ttl": "168h", "max_lease_ttl": "720h", '
                        '"disable_mlock": true, '
                        '"cluster_addr": "http://127.0.1.1:8201", '
                        '"api_addr": "http://127.0.1.1:8200"}',
                        "VAULT_API_ADDR": "http://[::]:8200",
                    },
                }
            },
        }

        self.harness.container_pebble_ready(container_name="vault")

        updated_plan = self.harness.get_container_pebble_plan("vault").to_dict()
        self.assertEqual(updated_plan, expected_plan)

    @patch("ops.model.Container.exec")
    @patch("charm.VaultCharm._bind_address")
    def test_given_unsecure_config_not_set_when_pebble_ready_then_unit_is_in_waiting_status(
        self, _, __
    ):
        self.harness.container_pebble_ready(container_name="vault")

        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus("Waiting for `authorise-charm` action to be triggered."),
        )

    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesProvidesV1.set_relation_certificate"  # noqa: E501,W505
    )
    @patch("vault.Vault.issue_certificate")
    def test_given_certificate_request_contains_correct_information_when_certificate_request_then_vault_is_called(  # noqa: E501
        self, patch_issue_certs, _
    ):
        certificate_signing_request = "whatever csr"

        event = Mock()
        event.certificate_signing_request = certificate_signing_request

        self.harness.charm._on_certificate_creation_request(event=event)

        calls = [call(certificate_signing_request=certificate_signing_request)]
        patch_issue_certs.assert_has_calls(calls=calls)

    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesProvidesV1.set_relation_certificate"  # noqa: E501, W505
    )
    @patch("vault.Vault.issue_certificate")
    def test_given_vault_answers_with_certificate_when_certificate_request_then_certificates_are_added_to_relation_data(  # noqa: E501
        self, patch_issue_certs, patch_set_relation_certs
    ):
        certificate_signing_request = "whatever csr"
        certificate = "whatever certificate"
        relation_id = 3
        issuing_ca = "whatever issuing ca"
        ca_chain = "whatever ca chain"
        patch_issue_certs.return_value = {
            "certificate": certificate,
            "issuing_ca": issuing_ca,
            "ca_chain": ca_chain,
        }
        event = Mock()

        event.certificate_signing_request = certificate_signing_request
        event.relation_id = relation_id

        self.harness.charm._on_certificate_creation_request(event=event)

        calls = [
            call(
                certificate=certificate,
                certificate_signing_request=certificate_signing_request,
                ca=issuing_ca,
                chain=ca_chain,
                relation_id=relation_id,
            )
        ]
        patch_set_relation_certs.assert_has_calls(calls=calls)

    @patch("vault.Vault.get_approle_auth_data")
    @patch("vault.Vault.is_ready", new_callable=PropertyMock)
    @patch("vault.Vault.generate_root_certificate")
    @patch("vault.Vault.create_local_charm_access_approle")
    @patch("vault.Vault.write_charm_pki_role")
    @patch("vault.Vault.enable_secrets_engine")
    @patch("vault.Vault.approle_login")
    @patch("vault.Vault.create_local_charm_policy")
    @patch("vault.Vault.enable_approle_auth")
    def test_given_vault_not_ready_when_on_authorise_charm_action_then_root_ca_is_generated(
        self,
        _,
        __,
        ___,
        ____,
        _____,
        ______,
        patch_generate_root_certificate,
        patch_vault_is_ready,
        patch_get_approle_auth_data,
    ):
        patch_vault_is_ready.return_value = False
        patch_get_approle_auth_data.return_value = "a", "b"
        event = Mock()
        event.params = {"token": "whatever token"}
        self.harness.set_leader()

        self.harness.charm._on_authorise_charm_action(event)

        patch_generate_root_certificate.assert_called()

    @patch("vault.Vault.get_approle_auth_data")
    @patch("vault.Vault.is_ready", new_callable=PropertyMock)
    @patch("vault.Vault.create_local_charm_access_approle")
    @patch("vault.Vault.approle_login")
    @patch("vault.Vault.create_local_charm_policy")
    @patch("vault.Vault.enable_approle_auth")
    def test_given_unit_is_leader_when_on_authorise_charm_action_then_status_is_active(
        self,
        _,
        __,
        ___,
        patch_create_local_charm_access_approle,
        patch_vault_ready,
        patch_get_approle_auth_data,
    ):
        patch_get_approle_auth_data.return_value = "a", "b"
        patch_create_local_charm_access_approle.return_value = "whatever id"
        patch_vault_ready.return_value = True
        event = Mock()
        event.params = {"token": "whatever token"}
        self.harness.set_leader()

        self.harness.charm._on_authorise_charm_action(event)

        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())
