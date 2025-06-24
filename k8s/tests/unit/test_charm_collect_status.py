#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from vault.vault_client import VaultClientError

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmCollectUnitStatus(VaultCharmFixtures):
    def test_given_invalid_log_level_config_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        state_in = testing.State(
            config={"log_level": "not valid"},
        )
        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("log_level config is not valid")

    def test_given_cant_connect_when_collect_unit_status_then_status_is_waiting(self):
        container = testing.Container(
            name="vault",
            can_connect=False,
        )
        state_in = testing.State(
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting to be able to connect to vault unit"
        )

    def test_given_peer_relation_not_created_when_collect_unit_status_then_status_is_waiting(self):
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for peer relation")

    def test_ca_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )

        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for CA certificate to be accessible in the charm"
        )

    def test_given_tls_ca_secret_doesnt_exist_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": False,
                "tls_file_pushed_to_workload.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for CA certificate secret")

    def test_given_tls_ca_not_pushed_to_workload_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for CA certificate to be shared")

    def test_given_vault_api_not_available_when_then_status_is_waiting(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for vault to be available")

    def test_given_tls_certificates_pki_relation_and_pki_ca_common_name_not_set_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = testing.Relation(
            endpoint="tls-certificates-pki",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation, pki_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Common name is not set in the charm config, cannot configure PKI secrets engine"
        )

    def test_given_tls_certificates_pki_relation_and_allowed_domains_is_invalid_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = testing.Relation(
            endpoint="tls-certificates-pki",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation, pki_relation],
            config={
                "pki_allowed_domains": "This should have been a comma separated list",
                "pki_ca_common_name": "myhostname.com",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Config value for pki_allowed_domains is not valid, it must be a comma separated list"
        )

    def test_given_tls_certificates_pki_relation_and_pki_ca_sans_dns_is_invalid_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = testing.Relation(
            endpoint="tls-certificates-pki",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation, pki_relation],
            config={
                "pki_ca_sans_dns": "This should have been a comma separated list",
                "pki_ca_common_name": "myhostname.com",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Config value for pki_ca_sans_dns is not valid, it must be a comma separated list"
        )

    def test_given_tls_certificates_acme_relation_and_common_name_not_set_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        acme_relation = testing.Relation(
            endpoint="tls-certificates-acme",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation, acme_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Common name is not set in the charm config, cannot configure ACME server"
        )

    def test_given_vault_uninitialized_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "is_seal_type_transit.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please initialize Vault")

    def test_given_uninitialized_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "is_seal_type_transit.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Please initialize Vault or integrate with an auto-unseal provider"
        )

    def test_given_vault_needs_migration_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": True,
                "needs_migration.return_value": True,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please migrate Vault")

    def test_given_vault_is_sealed_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": True,
                "needs_migration.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please unseal Vault")

    def test_given_vault_client_error_when_collect_unit_status_then_status_is_maintenance(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.side_effect": VaultClientError(),
                "needs_migration.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == MaintenanceStatus(
            "Seal check failed, waiting for Vault to recover"
        )

    def test_given_approle_secret_not_created_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "needs_migration.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Please authorize charm (see `authorize-charm` action)"
        )

    def test_given_vault_not_active_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "needs_migration.return_value": False,
                "is_active_or_standby.return_value": False,
            },
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
            secrets=[approle_secret],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for vault to finish raft leader election"
        )

    def test_given_vault_active_when_collect_unit_status_then_status_is_active(self):
        self.mock_tls.configure_mock(
            **{
                "tls_file_available_in_charm.return_value": True,
                "ca_certificate_secret_exists.return_value": True,
                "tls_file_pushed_to_workload.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "needs_migration.return_value": False,
                "is_active_or_standby.return_value": True,
            },
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            relations=[peer_relation],
            secrets=[approle_secret],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus()
