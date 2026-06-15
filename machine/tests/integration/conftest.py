#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import jubilant
import pytest

from config import APP_NAME, MICROCEPH_RGW_PORT

logger = logging.getLogger(__name__)

# jubilant's default ``wait_timeout`` is 180s, which is too short for several
# deploy/settle waits that don't pass an explicit timeout. Match the previous
# pytest-operator behaviour with a more generous default.
DEFAULT_WAIT_TIMEOUT = 60 * 10

_module_failures: set[str] = set()
_aborted_modules: set[str] = set()


def _module_file(item: pytest.Item) -> str | None:
    return getattr(getattr(item, "module", None), "__file__", None)


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    """Track module failures for juju-crashdump and ``abort_on_fail`` handling."""
    if call.when != "call" or call.excinfo is None:
        return
    module_file = _module_file(item)
    if not module_file:
        return
    _module_failures.add(module_file)
    if item.get_closest_marker("abort_on_fail") is not None:
        _aborted_modules.add(module_file)


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip remaining tests in a module once an ``abort_on_fail`` test has failed."""
    if item.get_closest_marker("abort_on_fail") is None:
        return
    if _module_file(item) in _aborted_modules:
        pytest.skip("Previous test marked with abort_on_fail failed in this module.")


@pytest.fixture(autouse=True, scope="module")
def set_juju_wait_timeout(juju: jubilant.Juju) -> None:
    """Raise the default ``juju.wait`` timeout for waits without an explicit one."""
    juju.wait_timeout = DEFAULT_WAIT_TIMEOUT


@pytest.fixture(autouse=True, scope="module")
def collect_juju_crashdump(juju: jubilant.Juju, request: pytest.FixtureRequest) -> Iterator[None]:
    """Run juju-crashdump before model teardown if any test in this module failed."""
    model = juju.model
    module_file = str(request.module.__file__)
    yield
    if module_file in _module_failures and model is not None:
        logger.info("Running juju-crashdump for model %s", model)
        subprocess.run(
            ["juju-crashdump", "-s", "-m", model, "-o", "."],
            check=False,
            timeout=120,
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
    parser.addoption(
        "--no-deploy",
        action="store_true",
        default=False,
        help="Skip deployment and reuse existing model",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Validate the options provided by the user.

    This is a pytest hook that is called after command line options have been parsed.

    Args:
      config: The pytest configuration object.
    """
    charm_path = str(config.getoption("--charm_path"))
    kv_requirer_charm_path = config.getoption("--kv_requirer_charm_path")
    if not charm_path:
        pytest.exit("The --charm_path option is required. Tests aborted.")
    if not os.path.exists(charm_path):
        pytest.exit(f"The path specified does not exist: {charm_path}")
    if kv_requirer_charm_path and not os.path.exists(str(kv_requirer_charm_path)):
        pytest.exit(f"The path specified does not exist: {kv_requirer_charm_path}")
    config.addinivalue_line("markers", "abort_on_fail: abort remaining tests in module on failure")


@pytest.fixture(scope="session")
def vault_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--charm_path"))).resolve()


@pytest.fixture(scope="session")
def kv_requirer_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--kv_requirer_charm_path"))).resolve()


@pytest.fixture(scope="session")
def skip_deploy(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--no-deploy"))


@pytest.fixture(scope="module")
def host_ip(juju: jubilant.Juju) -> str:
    """Get the gateway IP of the unit, which should be the host IP where minio is running."""
    result = juju.exec(
        "ip route | grep 'default via' | awk '{print $3}'",
        unit=f"{APP_NAME}/leader",
    )
    return result.stdout.strip()


@pytest.fixture(scope="module")
def microceph_endpoint(host_ip: str) -> str:
    """Get the MicroCeph RGW S3-compatible endpoint reachable from the LXD units."""
    return f"http://{host_ip}:{MICROCEPH_RGW_PORT}"
