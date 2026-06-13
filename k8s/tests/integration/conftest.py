# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import jubilant
import pytest

logger = logging.getLogger(__name__)

_module_failures: set[str] = set()


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    """Track which test modules have failures so we can run juju-crashdump."""
    if call.when == "call" and call.excinfo is not None:
        module = getattr(item, "module", None)
        module_file = getattr(module, "__file__", None) if module is not None else None
        if module_file:
            _module_failures.add(str(module_file))


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
    parser.addoption(
        "--charm_path",
        action="store",
        default=None,
        help="Path to the charm to deploy for testing",
    )
    parser.addoption(
        "--kv_requirer_charm_path",
        action="store",
        default=None,
        help="Path to the vault-kv-requirer charm to deploy for testing",
    )
    parser.addoption(
        "--pki_requirer_charm_path",
        action="store",
        default=None,
        help="Path to the vault-pki-requirer charm to deploy for testing",
    )
    parser.addoption(
        "--no-deploy",
        action="store_true",
        default=False,
        help="Skip deployment and reuse existing model",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Validate the options provided by the user and register custom markers.

    This is a pytest hook that is called after command line options have been parsed.

    Args:
      config: The pytest configuration object.
    """
    config.addinivalue_line("markers", "abort_on_fail: abort remaining tests in module on failure")
    charm_path = str(config.getoption("--charm_path"))
    kv_requirer_charm_path = str(config.getoption("--kv_requirer_charm_path"))
    if not charm_path:
        pytest.exit("The --charm_path option is required. Tests aborted.")
    if not os.path.exists(charm_path):
        pytest.exit(f"The path specified for the charm under test does not exist: {charm_path}")
    if kv_requirer_charm_path and kv_requirer_charm_path != "None":
        if not os.path.exists(kv_requirer_charm_path):
            pytest.exit(
                f"The path specified for KV Requirer does not exist: {kv_requirer_charm_path}"
            )


@pytest.fixture(scope="session")
def vault_charm_path(request: pytest.FixtureRequest) -> Path | None:
    charm_path = request.config.getoption("--charm_path")
    if charm_path:
        return Path(charm_path)
    return None


@pytest.fixture(scope="session")
def kv_requirer_charm_path(request: pytest.FixtureRequest) -> Path | None:
    path = request.config.getoption("--kv_requirer_charm_path")
    if not path:
        return None
    return Path(str(path)).resolve()


@pytest.fixture(scope="session")
def pki_requirer_charm_path(request: pytest.FixtureRequest) -> Path | None:
    path = request.config.getoption("--pki_requirer_charm_path")
    return Path(path) if path else None


@pytest.fixture(scope="session")
def skip_deploy(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--no-deploy"))
