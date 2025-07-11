#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing
import pytest
import requests
from vault.vault_managers import ManagerError

from fixtures import VaultCharmFixtures


class TestCharmRestoreBackupAction(VaultCharmFixtures):
    def test_given_manager_raises_error_when_list_backup_then_action_fails(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_backup_manager.list_backups.side_effect = ManagerError("some error message")
        response = requests.Response()
        response.status_code = 200
        self.mock_vault.configure_mock(
            **{
                "restore_snapshot.return_value": response,
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
        s3_relation = testing.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            relations=[peer_relation, s3_relation],
            secrets=[approle_secret],
        )

        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert e.value.message == "Failed to list backups: some error message"
