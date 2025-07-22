#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import ops.testing as testing
import pytest
import vault.testing.charm_authorize_action
from ops.testing import ActionFailed

from fixtures import VaultCharmFixtures


class TestCharmAuthorizeAction(VaultCharmFixtures, vault.testing.charm_authorize_action.Tests):
    def networks(self):
        bind_address = testing.BindAddress([testing.Address("1.2.1.2")])
        return [testing.Network("vault-peers", bind_addresses=[bind_address])]

    def test_given_api_address_unavailable_when_authorize_charm_then_fails(self):
        # Only the machine charm will raise this error, as the k8s charm always returns an address
        self.mock_vault.configure_mock(**{"authenticate.return_value": False})
        secret = testing.Secret(tracked_content={"token": "my token"})
        state_in = testing.State(leader=True, secrets=[secret])
        event = self.ctx.on.action("authorize-charm", params={"secret-id": secret.id})
        with pytest.raises(ActionFailed) as e:
            self.ctx.run(event, state_in)
        assert e.value.message == "API address is not available."
