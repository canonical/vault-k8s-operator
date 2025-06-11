#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from pathlib import Path

import pytest

pytest_plugins = (
    "tests.integration.charm_states.grafana",
    "tests.integration.charm_states.ha_proxy",
    "tests.integration.charm_states.s3_integrator",
    "tests.integration.charm_states.self_signed_certificates",
    "tests.integration.charm_states.vault",
    "tests.integration.charm_states.vault_kv_requirer",
    "tests.integration.charm_states.vault_pki_requirer",
)


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add options to the pytest command line.

    This is a pytest hook that is called when the pytest command line is being parsed.

    Args:
      parser: The pytest command line parser.
    """
    parser.addoption(
        "--charm_path", action="store", required=True, help="Path to the charm under test"
    )
    parser.addoption(
        "--kv_requirer_charm_path",
        action="store",
        default=None,
        help="Path to the KV requirer charm",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Validate the options provided by the user.

    This is a pytest hook that is called after command line options have been parsed.

    Args:
      config: The pytest configuration object.
    """
    charm_path = str(config.getoption("--charm_path"))
    kv_requirer_charm_path = str(config.getoption("--kv_requirer_charm_path"))
    if not charm_path:
        pytest.exit("The --charm_path option is required. Tests aborted.")
    if not kv_requirer_charm_path:
        pytest.exit("The --kv_requirer_charm_path option is required. Tests aborted.")
    if not os.path.exists(charm_path):
        pytest.exit(f"The path specified does not exist: {charm_path}")
    if not os.path.exists(kv_requirer_charm_path):
        pytest.exit(f"The path specified does not exist: {kv_requirer_charm_path}")


@pytest.fixture(scope="session")
def vault_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--charm_path"))).resolve()


@pytest.fixture(scope="session")
def kv_requirer_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--kv_requirer_charm_path"))).resolve()
