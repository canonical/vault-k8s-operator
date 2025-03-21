#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
import pytest
from ops.testing import ActionFailed

from vault.vault_managers import ManagerError
from tests.unit.fixtures import VaultCharmFixtures


class TestCharmCreateBackupAction(VaultCharmFixtures):
    def test_given_failed_to_initialize_vault_client_when_create_backup_then_action_fails(self):
        state_in = testing.State(
            leader=True,
            relations=[],
        )
        with pytest.raises(ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("create-backup"), state_in)

        assert e.value.message == "Failed to initialize Vault client."

    def test_given_manager_raises_error_when_create_backup_then_action_fails(self):
        self.mock_backup_manager.create_backup.side_effect = ManagerError("some error message")

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
            self.ctx.run(self.ctx.on.action("create-backup"), state_in)
        assert e.value.message == "Failed to create backup: some error message"
