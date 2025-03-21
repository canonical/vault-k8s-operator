#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
import pytest
from ops.testing import ActionFailed

from vault.vault_managers import ManagerError
from tests.unit.fixtures import VaultCharmFixtures


class TestCharmBootstrapRaftAction(VaultCharmFixtures):
    def test_given_no_network_when_bootstrap_raft_action_then_fails(self):
        state_in = testing.State(
            leader=True,
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("bootstrap-raft"), state_in)
        assert e.value.message == "Network bind address is not available"

    def test_when_bootstrap_raft_raises_manager_error_then_action_fails_with_error_message(self):
        self.mock_raft_manager.bootstrap.side_effect = ManagerError("some error message")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            leader=False,
            relations=[peer_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )

        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("bootstrap-raft"), state_in)
        assert e.value.message == "Failed to bootstrap raft: some error message"
