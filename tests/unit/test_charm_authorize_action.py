#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import ops.testing as testing
import pytest
from charms.vault_k8s.v0.vault_client import AuditDeviceType, VaultClientError

from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class TestCharmAuthorizeAction(VaultCharmFixtures):
    def test_given_unit_not_leader_when_authorize_charm_then_action_fails(self):
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            leader=False,
        )
        with pytest.raises(testing.ActionFailed) as exc:
            self.ctx.run(self.ctx.on.action("authorize-charm"), state=state_in)
        assert "This action must be run on the leader unit." in exc.value.message

    def test_given_secret_id_not_found_when_authorize_charm_then_action_fails(self):
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
        )

        with pytest.raises(testing.ActionFailed) as exc:
            self.ctx.run(
                self.ctx.on.action("authorize-charm", params={"secret-id": "my secret id"}),
                state=state_in,
            )
        assert (
            "The secret id provided could not be found by the charm. Please grant the token secret to the charm."
            == exc.value.message
        )

    def test_given_no_token_when_authorize_charm_then_action_fails(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        user_provided_secret = testing.Secret(
            tracked_content={"no-token": "no token"},
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[user_provided_secret],
        )
        with pytest.raises(testing.ActionFailed) as exc:
            self.ctx.run(
                self.ctx.on.action(
                    "authorize-charm", params={"secret-id": user_provided_secret.id}
                ),
                state=state_in,
            )
        assert (
            "Token not found in the secret. Please provide a valid token secret."
            == exc.value.message
        )

    def test_given_invalid_token_when_authorize_charm_then_action_fails(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": False,
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        user_provided_secret = testing.Secret(
            tracked_content={"token": "invalid token"},
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[user_provided_secret],
        )
        with pytest.raises(testing.ActionFailed) as exc:
            self.ctx.run(
                self.ctx.on.action(
                    "authorize-charm", params={"secret-id": user_provided_secret.id}
                ),
                state=state_in,
            )
        assert (
            "The token provided is not valid. Please use a Vault token with the appropriate permissions."
            == exc.value.message
        )

    def test_given_vault_client_error_when_authorize_charm_then_action_fails(self):
        my_error_message = "my error message"
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "enable_audit_device.side_effect": VaultClientError(my_error_message),
            },
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        user_provided_secret = testing.Secret(
            tracked_content={"token": "my token"},
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[user_provided_secret],
        )
        with pytest.raises(testing.ActionFailed) as exc:
            self.ctx.run(
                self.ctx.on.action(
                    "authorize-charm", params={"secret-id": user_provided_secret.id}
                ),
                state=state_in,
            )
        assert (
            f"Vault returned an error while authorizing the charm: {my_error_message}"
            == exc.value.message
        )

    def test_given_when_authorize_charm_then_charm_is_authorized(self):
        self.mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "create_or_update_approle.return_value": "my-role-id",
                "generate_role_secret_id.return_value": "my-secret-id",
            },
        )
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4",
            ingress_address="1.2.3.4",
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        user_provided_secret = testing.Secret(
            tracked_content={"token": "my token"},
        )
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            containers=[container],
            leader=True,
            secrets=[user_provided_secret],
            relations=[peer_relation],
        )
        state_out = self.ctx.run(
            self.ctx.on.action("authorize-charm", params={"secret-id": user_provided_secret.id}),
            state=state_in,
        )

        self.mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        self.mock_vault.enable_approle_auth_method.assert_called_once()
        self.mock_vault.create_or_update_policy_from_file.assert_called_once_with(
            name="charm-access",
            path="src/templates/charm_policy.hcl",
        )
        self.mock_vault.create_or_update_approle.assert_called_once_with(
            name="charm",
            cidrs=["1.2.3.4/24"],
            policies=["charm-access", "default"],
            token_ttl="1h",
            token_max_ttl="1h",
        )
        assert self.ctx.action_results == {
            "result": "Charm authorized successfully. You may now remove the secret."
        }
        assert state_out.get_secret(label="vault-approle-auth-details").tracked_content == {
            "role-id": "my-role-id",
            "secret-id": "my-secret-id",
        }
