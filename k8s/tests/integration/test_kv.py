import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_1_APPLICATION_NAME,
    VAULT_KV_REQUIRER_2_APPLICATION_NAME,
)
from helpers import (
    crash_pod,
    deploy_vault,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(
    ops_test: OpsTest, vault_charm_path: Path, kv_requirer_charm_path: Path, skip_deploy: bool
) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APPLICATION_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        kv_requirer_charm_path,
        application_name=VAULT_KV_REQUIRER_1_APPLICATION_NAME,
    )

    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
        ops_test.model.wait_for_idle(
            apps=[VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
        ),
    )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:vault-kv",
        relation2=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}:vault-kv",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    secret_key = "test-key"
    secret_value = "test-value"
    vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
    vault_kv_unit = vault_kv_application.units[0]
    vault_kv_create_secret_action = await vault_kv_unit.run_action(
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    await ops_test.model.get_action_output(
        action_uuid=vault_kv_create_secret_action.entity_id, wait=30
    )

    vault_kv_get_secret_action = await vault_kv_unit.run_action(
        action_name="get-secret",
        key=secret_key,
    )

    action_output = await ops_test.model.get_action_output(
        action_uuid=vault_kv_get_secret_action.entity_id, wait=30
    )

    assert action_output["value"] == secret_value


@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_related_and_requirer_pod_crashes_when_create_secret_then_secret_is_created(
    ops_test: OpsTest, deploy: VaultInit
):
    secret_key = "test-key"
    secret_value = "test-value"
    assert ops_test.model
    vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
    vault_kv_unit = vault_kv_application.units[0]
    k8s_namespace = ops_test.model.name

    crash_pod(
        name=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}-0",
        namespace=k8s_namespace,
    )

    await ops_test.model.wait_for_idle(
        apps=[VAULT_KV_REQUIRER_1_APPLICATION_NAME],
        status="active",
        wait_for_exact_units=1,
    )

    vault_kv_create_secret_action = await vault_kv_unit.run_action(
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    await ops_test.model.get_action_output(
        action_uuid=vault_kv_create_secret_action.entity_id, wait=30
    )

    vault_kv_get_secret_action = await vault_kv_unit.run_action(
        action_name="get-secret",
        key=secret_key,
    )

    action_output = await ops_test.model.get_action_output(
        action_uuid=vault_kv_get_secret_action.entity_id, wait=30
    )

    assert action_output["value"] == secret_value


@pytest.mark.abort_on_fail
async def test_given_multiple_kv_requirers_related_when_secrets_created_then_secrets_created(
    ops_test: OpsTest, kv_requirer_charm_path: Path
):
    assert ops_test.model
    await ops_test.model.deploy(
        kv_requirer_charm_path,
        application_name=VAULT_KV_REQUIRER_2_APPLICATION_NAME,
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[VAULT_KV_REQUIRER_2_APPLICATION_NAME],
        )
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:vault-kv",
        relation2=f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}:vault-kv",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_2_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )
    secret_key = "test-key-2"
    secret_value = "test-value-2"
    assert ops_test.model
    vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_2_APPLICATION_NAME]
    assert isinstance(vault_kv_application, Application)
    vault_kv_unit = vault_kv_application.units[0]
    vault_kv_create_secret_action = await vault_kv_unit.run_action(
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    await ops_test.model.get_action_output(
        action_uuid=vault_kv_create_secret_action.entity_id, wait=30
    )

    vault_kv_get_secret_action = await vault_kv_unit.run_action(
        action_name="get-secret",
        key=secret_key,
    )

    action_output = await ops_test.model.get_action_output(
        action_uuid=vault_kv_get_secret_action.entity_id, wait=30
    )

    assert action_output["value"] == secret_value
