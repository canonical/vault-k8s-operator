#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
import pytest

from vault.vault_managers import ManagerError
from tests.unit.fixtures import VaultCharmFixtures


class TestCharmRestoreBackupAction(VaultCharmFixtures):
    def test_given_manager_raises_error_when_restore_backup_then_action_fails(self):
        self.mock_backup_manager.restore_backup.side_effect = ManagerError("some error message")

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
            peers_data={
                1: {"node_api_address": "1.2.3.4"},
            },
        )
        state_in = testing.State(
            leader=True,
            relations=[s3_relation, peer_relation],
            secrets=[approle_secret],
        )
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(
                self.ctx.on.action("restore-backup", params={"backup-id": "my-backup-id"}),
                state_in,
            )
        assert e.value.message == "Failed to restore backup: some error message"
