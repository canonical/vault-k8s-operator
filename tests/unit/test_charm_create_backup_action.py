#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import scenario
from charms.vault_k8s.v0.vault_s3 import S3Error

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmCreateBackupAction(VaultCharmFixtures):
    def test_given_non_leader_when_create_backup_action_then_fails(self):
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=False,
        )
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert (
            action_output.failure
            == "S3 pre-requisites not met. Only leader unit can perform backup operations."
        )

    def test_given_s3_relation_not_created_when_create_backup_action_then_fails(self):
        container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
        )
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "S3 pre-requisites not met. S3 relation not created."

    def test_given_missing_s3_parameters_when_create_backup_then_action_fails(self):
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert (
            action_output.failure
            == "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint):."
        )

    def test_given_s3_error_when_create_backup_then_action_fails(self):
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to create S3 session."

    def test_given_bucket_creation_returns_none_when_create_backup_then_action_fails(self):
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
                "create_bucket.return_value": None,
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to create S3 bucket."

    def test_given_failed_to_initialize_vault_client_when_create_backup_then_action_fails(self):
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to initialize Vault client."

    def test_given_failed_to_upload_backup_when_create_backup_then_action_fails(self):
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
                "upload_content.return_value": False,
            },
        )
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_active_or_standby.return_value": True,
            },
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to upload backup to S3 bucket."

    def test_given_s3_available_when_create_backup_then_backup_created(self):
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
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_active_or_standby.return_value": True,
            },
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
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
        action = scenario.Action(
            name="create-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        self.mock_s3.return_value.create_bucket.assert_called_with(bucket_name="my bucket")
        self.mock_vault.create_snapshot.assert_called()
        self.mock_s3.return_value.upload_content.assert_called()
        assert action_output.success is True
        assert action_output.results
        assert "backup-id" in action_output.results
