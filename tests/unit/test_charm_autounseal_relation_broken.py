#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import ops.testing as testing

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmAutounsealRelationBroken(VaultCharmFixtures):
    def test_when_autounseal_destroy_then_credentials_are_removed(self):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
            },
        )
        autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        container = testing.Container(
            name="vault",
            can_connect=True,
        )
        state_in = testing.State(
            leader=True,
            containers=[container],
            relations=[autounseal_relation],
            secrets=[approle_secret],
        )

        self.ctx.run(self.ctx.on.relation_broken(autounseal_relation), state_in)

        self.mock_vault.destroy_autounseal_credentials.assert_called_once_with(
            autounseal_relation.id, "charm-autounseal"
        )
