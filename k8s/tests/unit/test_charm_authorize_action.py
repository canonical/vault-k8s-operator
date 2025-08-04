#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import vault.testing.charm_authorize_action
from ops import testing

from fixtures import MockBinding, VaultCharmFixtures


class TestCharmAuthorizeAction(VaultCharmFixtures, vault.testing.charm_authorize_action.Tests):
    def containers(self):
        return [testing.Container(name="vault", can_connect=True)]

    def test_given_when_authorize_charm_then_charm_is_authorized(self):
        self.mock_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.2.3.4"
        )
        super().test_given_when_authorize_charm_then_charm_is_authorized()
