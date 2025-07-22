"""Common test cases for the authorize-charm action."""

# ruff: noqa: D101, D102

import typing
import unittest.mock

import ops
import pytest
from ops import testing

from vault.vault_client import AuditDeviceType, VaultClientError


class Tests:
    # attributes provided by {k8s,machine}/tests/unit/fixtures.VaultCharmFixtures
    ctx: testing.Context
    charm_type: type[ops.CharmBase]
    mock_tls: unittest.mock.MagicMock
    mock_lib_vault: unittest.mock.MagicMock

    def relations(self):
        return [testing.PeerRelation(endpoint="vault-peers")]

    # k8s tests override this
    def containers(self) -> typing.Iterable[testing.Container]:
        return ()

    # machine tests override this
    def networks(self) -> typing.Iterable[testing.Network]:
        return ()

    def test_given_unit_not_leader_when_authorize_charm_then_action_fails(self):
        state_in = testing.State(containers=self.containers(), leader=False)
        event = self.ctx.on.action("authorize-charm")
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == "This action must be run on the leader unit."

    def test_given_secret_id_not_found_when_authorize_charm_then_action_fails(self):
        state_in = testing.State(containers=self.containers(), leader=True)
        event = self.ctx.on.action("authorize-charm", params={"secret-id": "my secret id"})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == (
            "The secret id provided could not be found by the charm."
            " Please grant the token secret to the charm."
        )

    def test_given_no_token_when_authorize_charm_then_action_fails(self):
        secret = testing.Secret(tracked_content={"no-token": "no token"})
        state_in = testing.State(containers=self.containers(), leader=True, secrets=[secret])
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == (
            "Token not found in the secret. Please provide a valid token secret."
        )

    def test_given_ca_certificate_unavailable_when_authorize_charm_then_fails(self):
        self.mock_tls.configure_mock(**{"tls_file_available_in_charm.return_value": False})
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            relations=self.relations(),
            leader=True,
            secrets=[secret],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state_in)
        assert e.value.message == (
            "CA certificate is not available in the charm. Something is wrong."
        )

    def test_given_vault_client_error_when_authorize_charm_then_action_fails(self):
        msg = "my error message"
        self.mock_lib_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "enable_audit_device.side_effect": VaultClientError(msg),
            }
        )
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            relations=self.relations(),
            leader=True,
            secrets=[secret],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == f"Vault returned an error while authorizing the charm: {msg}"

    def test_given_invalid_token_when_authorize_charm_then_action_fails(self):
        self.mock_lib_vault.configure_mock(**{"authenticate.return_value": False})
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            relations=self.relations(),
            leader=True,
            secrets=[secret],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(testing.ActionFailed) as e:
            self.ctx.run(event, state=state_in)
        assert e.value.message == (
            "The token provided is not valid."
            " Please use a Vault token with the appropriate permissions."
        )

    def test_given_when_authorize_charm_then_charm_is_authorized(self):
        mock_vault = self.mock_lib_vault
        mock_vault.configure_mock(
            **{
                "authenticate.return_value": True,
                "create_or_update_approle.return_value": "my-role-id",
                "generate_role_secret_id.return_value": "my-secret-id",
            },
        )
        secret = testing.Secret(tracked_content={"token": "invalid token"})
        state_in = testing.State(
            containers=self.containers(),
            networks=self.networks(),
            relations=self.relations(),
            leader=True,
            secrets=[secret],
        )
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        state_out = self.ctx.run(event, state=state_in)
        mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        mock_vault.enable_approle_auth_method.assert_called_once()
        mock_vault.create_or_update_policy_from_file.assert_called_once_with(
            name="charm-access",
            path="src/templates/charm_policy.hcl",
        )
        mock_vault.create_or_update_approle.assert_called_once_with(
            name="charm",
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
