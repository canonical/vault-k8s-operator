#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
import pytest

from lib.vault_managers import ManagerError
from tests.unit.fixtures import VaultCharmFixtures


class TestCharmListBackupAction(VaultCharmFixtures):
    def test_given_manager_raises_error_when_list_backups_then_action_fails(self):
        self.mock_backup_manager.list_backups.side_effect = ManagerError("some error message")

        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        s3_relation = testing.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            leader=True,
            relations=[s3_relation, peer_relation],
            secrets=[approle_secret],
        )
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert e.value.message == "Failed to list backups: some error message"
