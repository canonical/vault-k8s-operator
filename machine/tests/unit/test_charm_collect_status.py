#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock

import ops.testing as testing
from charms.operator_libs_linux.v2.snap import Snap
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

from lib.vault_client import VaultClientError
from tests.unit.fixtures import VaultCharmFixtures


class TestCharmCollectUnitStatus(VaultCharmFixtures):
    def test_given_tls_relation_and_bad_common_name_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        tls_relation = testing.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
        )
        state_in = testing.State(
            config={"common_name": ""},
            relations=[tls_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Common name is not set in the charm config, cannot configure PKI secrets engine"
        )

    def test_given_peer_relation_not_created_when_collect_unit_status_then_status_is_waiting(self):
        state_in = testing.State(
            relations=[],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for peer relation")

    def test_given_bind_address_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            relations=[peer_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("")])],
                )
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for bind address")

    def test_given_non_leader_and_unit_address_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for other units to provide their addresses"
        )

    def test_given_ca_certificate_not_available_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for CA certificate in workload")

    def test_given_certificate_unavailable_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Certificate is unavailable in the charm")

    def test_given_service_not_started_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(spec=Snap, revision="1.16/stable", services={})
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Vault service to start")

    def test_given_vault_api_unavailable_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Vault API is not yet available")

    def test_given_vault_uninitialized_and_seal_type_transit_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "is_seal_type_transit.return_value": True,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please initialize Vault")

    def test_given_vault_uninitialized_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "is_seal_type_transit.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Please initialize Vault or integrate with an auto-unseal provider"
        )

    def test_given_vault_sealed_and_needs_migration_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_seal_type_transit.return_value": False,
                "is_sealed.return_value": True,
                "needs_migration.return_value": True,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please migrate Vault")

    def test_given_vault_sealed_and_doesnt_need_migration_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_seal_type_transit.return_value": False,
                "is_sealed.return_value": True,
                "needs_migration.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Please unseal Vault")

    def test_given_vault_client_error_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_seal_type_transit.return_value": False,
                "is_sealed.side_effect": VaultClientError(),
                "needs_migration.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == MaintenanceStatus(
            "Seal check failed, waiting for Vault to recover"
        )

    def test_given_vault_unauthorized_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_seal_type_transit.return_value": False,
                "is_sealed.return_value": False,
                "needs_migration.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        state_in = testing.State(
            relations=[peer_relation],
            planned_units=3,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Please authorize charm (see `authorize-charm` action)"
        )

    def test_given_vault_authorized_when_collect_unit_status_then_status_is_active(
        self,
    ):
        self.mock_snap_cache.return_value = {
            "vault": MagicMock(
                spec=Snap, revision="1.16/stable", services={"vaultd": {"active": True}}
            )
        }
        self.mock_tls.configure_mock(
            **{
                "tls_file_pushed_to_workload.return_value": True,
                "tls_file_available_in_charm.return_value": True,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_seal_type_transit.return_value": False,
                "is_sealed.return_value": False,
                "needs_migration.return_value": False,
            },
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
                2: {"node_api_address": "1.2.3.5"},
                3: {"node_api_address": "1.2.3.6"},
            },
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={
                "role-id": "existing role id",
                "secret-id": "existing secret id",
            },
        )
        state_in = testing.State(
            relations=[peer_relation], planned_units=3, secrets=[approle_secret]
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus()
