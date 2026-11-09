#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import signal
from io import StringIO
from unittest.mock import patch

import hcl
import ops.testing as testing
import pytest
from charms.operator_libs_linux.v2.snap import SnapError
from ops import WaitingStatus
from vault.vault_client import VaultClientError
from vault.vault_helpers import ConfigAction

from fixtures import VaultCharmFixtures

CONFIG_PATH = "/var/snap/vault/common/vault.hcl"
LEADER_ADDRESS = "https://1.2.3.9:8200"
EXISTING_CONFIG = 'log_level = "info"\n'


class TestCharmVaultConfig(VaultCharmFixtures):
    @pytest.fixture(autouse=True)
    def setup_config(self):
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_vault.is_seal_type_transit.return_value = False
        self.mock_machine.pull.side_effect = lambda **_: StringIO(EXISTING_CONFIG)

    def _state(self, leader: bool, app_data: dict[str, str] | None = None) -> testing.State:
        return testing.State(
            unit_status=testing.ActiveStatus(),
            leader=leader,
            relations=[
                testing.PeerRelation(endpoint="vault-peers", local_app_data=app_data or {})
            ],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.3.4")])],
                )
            },
        )

    def _config_writes(self) -> list[str]:
        return [
            call.kwargs["source"]
            for call in self.mock_machine.push.call_args_list
            if call.kwargs["path"] == CONFIG_PATH
        ]

    def test_given_non_leader_and_no_leader_address_when_configure_then_vault_not_configured(self):
        self.ctx.run(self.ctx.on.config_changed(), self._state(False))

        assert self._config_writes() == []

    def test_given_non_leader_and_leader_address_when_configure_then_retry_join_has_leader(self):
        self.mock_machine.get_service.return_value = None
        state_in = self._state(False, {"leader_node_api_address": LEADER_ADDRESS})

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        retry_join = hcl.loads(self._config_writes()[-1])["storage"]["raft"]["retry_join"]
        assert retry_join["leader_api_addr"] == LEADER_ADDRESS

    def test_given_leader_when_configure_then_leader_address_is_shared(self):
        self.mock_machine.get_service.return_value = None

        state_out = self.ctx.run(self.ctx.on.config_changed(), self._state(True))

        peer_relation = state_out.get_relations("vault-peers")[0]
        assert peer_relation.local_app_data["leader_node_api_address"] == "https://1.2.3.4:8200"

    def _run_with_running_vault(self, action: ConfigAction | Exception) -> None:
        with patch("charm.get_config_action", side_effect=[action]):
            self.ctx.run(self.ctx.on.config_changed(), self._state(True))

    @pytest.mark.parametrize(
        "action,restarts,reloads",
        [
            (ConfigAction.RESTART, 1, 0),
            (ConfigAction.RELOAD, 0, 1),
            (ConfigAction.NONE, 0, 0),
        ],
    )
    def test_given_running_vault_when_config_changes_then_action_is_applied(
        self, action: ConfigAction, restarts: int, reloads: int
    ):
        self._run_with_running_vault(action)

        assert len(self._config_writes()) == 1
        assert self.mock_machine.restart.call_count == restarts
        assert self.mock_machine.send_signal.call_count == reloads
        if reloads:
            self.mock_machine.send_signal.assert_called_once_with(signal.SIGHUP, "vault")

    def test_given_vault_state_unknown_when_config_changes_then_existing_config_is_kept(self):
        self._run_with_running_vault(VaultClientError("Vault API is not available"))

        assert self._config_writes() == []
        self.mock_machine.restart.assert_not_called()

    def test_given_restart_fails_when_config_changes_then_existing_config_is_restored(self):
        self.mock_machine.restart.side_effect = SnapError("failed")

        self._run_with_running_vault(ConfigAction.RESTART)

        self.mock_machine.restart.assert_called_once_with("vault")
        assert self._config_writes()[-1] == EXISTING_CONFIG

    @pytest.mark.parametrize("leader", [True, False])
    def test_given_autounseal_details_not_available_when_configure_then_vault_not_configured(
        self, leader: bool
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=leader,
            relations=[
                testing.PeerRelation(
                    endpoint="vault-peers",
                    local_app_data={"leader_node_api_address": LEADER_ADDRESS},
                ),
                testing.Relation(
                    endpoint="vault-autounseal-requires", interface="vault-autounseal"
                ),
            ],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.3.4")])],
                )
            },
        )

        state_out = self.ctx.run(self.ctx.on.config_changed(), state_in)

        assert self._config_writes() == []
        self.mock_snap_cache.return_value.__getitem__.return_value.start.assert_not_called()
        assert state_out.unit_status == WaitingStatus("Waiting for auto-unseal details")
