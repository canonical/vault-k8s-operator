#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import json

import scenario
import pytest
from charms.vault_k8s.v0.vault_s3 import S3Error

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmListBackupAction(VaultCharmFixtures):
    def test_given_non_leader_when_list_backups_action_then_fails(self):
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=False,
        )
        with pytest.raises(scenario.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert (
            e.value.message
            == "S3 pre-requisites not met. Only leader unit can perform backup operations."
        )

    def test_given_s3_relation_not_created_when_list_backups_action_then_fails(self):
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
        )
        with pytest.raises(scenario.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert (
            e.value.message
            == "S3 pre-requisites not met. S3 relation not created."
        )

    def test_given_missing_s3_parameters_when_list_backups_then_action_fails(self):
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[s3_relation],
        )

        with pytest.raises(scenario.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert (
            e.value.message
            == "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint)."
        )

    def test_given_s3_error_during_instantiation_when_list_backups_then_action_fails(self):
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
        self.mock_s3.side_effect = S3Error()
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[s3_relation],
        )
        with pytest.raises(scenario.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert (
            e.value.message
            == "Failed to create S3 session."
        )

    def test_given_s3_error_during_get_object_key_when_list_backups_then_action_fails(self):
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
        self.mock_s3.return_value.configure_mock(
            **{
                "get_object_key_list.side_effect": S3Error(),
            },
        )
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[s3_relation],
        )
        with pytest.raises(scenario.ActionFailed) as e:
            self.ctx.run(self.ctx.on.action("list-backups"), state_in)
        assert (
            e.value.message
            == "Failed to run list-backups action - Failed to list backups."
        )

    def test_given_s3_available_when_list_backups_then_backup_listed(self):
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
        self.mock_s3.return_value.configure_mock(
            **{
                "upload_content.return_value": True,
            },
        )
        self.mock_s3.return_value.configure_mock(
            **{
                "get_object_key_list.return_value": ["my-backup-id"],
            },
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[s3_relation],
            secrets=[approle_secret],
        )

        self.ctx.run(self.ctx.on.action("list-backups"), state_in)

        assert self.ctx.action_results == {"backup-ids": json.dumps(["my-backup-id"])}
