#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import scenario

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
        autounseal_relation = scenario.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
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
        state_in = scenario.State(
            leader=True,
            containers=[container],
            relations=[autounseal_relation],
            secrets=[approle_secret],
        )

        self.ctx.run(autounseal_relation.broken_event, state_in)

        self.mock_vault.destroy_autounseal_credentials.assert_called_once_with(
            autounseal_relation.relation_id, "charm-autounseal"
        )
