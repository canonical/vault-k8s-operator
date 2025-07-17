# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import contextlib
from unittest.mock import patch

import ops.testing as testing
import pytest
from vault.testing.mocks import VaultCharmFixturesBase

from charm import VaultCharm


class VaultCharmFixtures(VaultCharmFixturesBase):
    @pytest.fixture(autouse=True)
    def setup(self):
        with (
            self.mocks(),  # common mocks from base class
            contextlib.ExitStack() as stack,
        ):
            stack.enter_context(self.mocks())
            # When we want to mock the instances, we use the return value of the mocked class
            # When we want to mock the callable, we use the mock directly
            self.mock_get_binding = stack.enter_context(patch("ops.model.Model.get_binding"))
            yield

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(charm_type=VaultCharm)


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)
