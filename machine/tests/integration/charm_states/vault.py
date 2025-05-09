import logging
from asyncio import Task, create_task
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.constants import APP_NAME, JUJU_FAST_INTERVAL, NUM_VAULT_UNITS
from tests.integration.helpers import (
    authorize_charm,
    deploy_vault_and_wait,
    get_ca_cert_file_location,
    initialize_vault_leader,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
async def vault_idle_blocked(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be blocked.

    This is the default state of Vault.
    """
    return create_task(
        deploy_vault_and_wait(ops_test, vault_charm_path, NUM_VAULT_UNITS, status="blocked")
    )


@pytest.fixture(scope="function")
async def vault_authorized(ops_test: OpsTest, vault_unsealed: Task) -> Task:
    """Ensure the Vault charm is authorized.

    This is the fully operational and "ready to go" state of Vault.
    """
    assert ops_test.model
    root_token, key = await vault_unsealed

    async def authorize():
        await authorize_charm(ops_test, root_token)
        return root_token, key

    return create_task(authorize())


@pytest.fixture(scope="function")
async def vault_initialized(ops_test: OpsTest, vault_idle: Task) -> Task:
    async def deploy_and_initialize():
        assert ops_test.model

        await vault_idle
        return await initialize_vault_leader(ops_test, APP_NAME)

    return create_task(deploy_and_initialize())


@pytest.fixture(scope="function")
async def vault_unsealed(ops_test: OpsTest, vault_initialized: Task) -> Task:
    assert ops_test.model
    root_token, unseal_key = await vault_initialized

    async def task():
        async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
            await unseal_all_vault_units(
                ops_test, await get_ca_cert_file_location(ops_test), unseal_key
            )
        return root_token, unseal_key

    return create_task(task())


@pytest.fixture(scope="function")
async def vault_idle(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be idle.

    This states does not require any particular workfload state, so it may be
    used when the test does not require the Vault charm to be initialized,
    unsealed, and authorized. A "blocked" state is acceptable, but so is an
    "active" state.
    """
    return create_task(deploy_vault_and_wait(ops_test, vault_charm_path, NUM_VAULT_UNITS))
