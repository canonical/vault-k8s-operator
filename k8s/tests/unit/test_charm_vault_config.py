#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import signal
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import hcl
import ops.testing as testing
import pytest
from ops import pebble
from vault.vault_client import VaultClientError
from vault.vault_helpers import ConfigAction

from charm import VaultCharm
from container import Container
from fixtures import VaultCharmFixtures

LEADER_ADDRESS = "https://vault-k8s-0.vault-k8s-endpoints:8200"
EXISTING_CONFIG = 'log_level = "info"\n'


class TestCharmVaultConfig(VaultCharmFixtures):
    @pytest.fixture(autouse=True)
    def setup_config(self):
        self.mock_socket_fqdn.return_value = "vault-k8s-1.vault-k8s-endpoints"
        self.mock_autounseal_requires_get_details.return_value = None
        with tempfile.TemporaryDirectory() as temp_dir:
            self.config_dir = Path(temp_dir)
            self.container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={"vault-config": testing.Mount(location="/vault/config", source=temp_dir)},
            )
            yield

    def _state(self, leader: bool, app_data: dict[str, str] | None = None) -> testing.State:
        return testing.State(
            containers=[self.container],
            leader=leader,
            relations=[
                testing.PeerRelation(endpoint="vault-peers", local_app_data=app_data or {})
            ],
        )

    def _retry_join_addresses(self) -> list[str]:
        config = hcl.loads((self.config_dir / "vault.hcl").read_text())
        retry_joins = config["storage"]["raft"].get("retry_join", [])
        if isinstance(retry_joins, dict):
            retry_joins = [retry_joins]
        return [retry_join["leader_api_addr"] for retry_join in retry_joins]

    def test_given_non_leader_and_no_leader_address_when_configure_then_vault_not_configured(self):
        state_out = self.ctx.run(self.ctx.on.pebble_ready(self.container), self._state(False))

        assert not (self.config_dir / "vault.hcl").exists()
        assert list(state_out.containers)[0].layers == {}

    def test_given_non_leader_and_leader_address_when_configure_then_retry_join_has_leader(self):
        state_in = self._state(False, {"leader_node_api_address": LEADER_ADDRESS})

        self.ctx.run(self.ctx.on.pebble_ready(self.container), state_in)

        assert self._retry_join_addresses() == [LEADER_ADDRESS]

    def test_given_leader_when_configure_then_leader_address_is_shared(self):
        state_out = self.ctx.run(self.ctx.on.pebble_ready(self.container), self._state(True))

        peer_relation = state_out.get_relations("vault-peers")[0]
        assert peer_relation.local_app_data["leader_node_api_address"] == (
            "https://vault-k8s-1.vault-k8s-endpoints:8200"
        )
        assert self._retry_join_addresses() == []

    def _run_with_running_vault(
        self, action: ConfigAction | Exception, restart_error: Exception | None = None
    ) -> tuple[MagicMock, MagicMock]:
        (self.config_dir / "vault.hcl").write_text(EXISTING_CONFIG)
        with (
            patch.object(VaultCharm, "_vault_service_is_running", return_value=True),
            patch.object(VaultCharm, "_pebble_plan_is_applied", return_value=True),
            patch("charm.get_config_action", side_effect=[action]),
            patch.object(Container, "restart", side_effect=restart_error) as restart,
            patch.object(Container, "send_signal") as send_signal,
        ):
            self.ctx.run(self.ctx.on.pebble_ready(self.container), self._state(True))
        return restart, send_signal

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
        restart, send_signal = self._run_with_running_vault(action)

        assert (self.config_dir / "vault.hcl").read_text() != EXISTING_CONFIG
        assert restart.call_count == restarts
        assert send_signal.call_count == reloads
        if reloads:
            send_signal.assert_called_once_with(signal.SIGHUP, "vault")

    def test_given_vault_state_unknown_when_config_changes_then_existing_config_is_kept(self):
        restart, _ = self._run_with_running_vault(VaultClientError("Vault API is not available"))

        assert (self.config_dir / "vault.hcl").read_text() == EXISTING_CONFIG
        restart.assert_not_called()

    def test_given_restart_fails_when_config_changes_then_existing_config_is_restored(self):
        restart, _ = self._run_with_running_vault(
            ConfigAction.RESTART, restart_error=pebble.ChangeError("failed", MagicMock())
        )

        restart.assert_called_once()
        assert (self.config_dir / "vault.hcl").read_text() == EXISTING_CONFIG
