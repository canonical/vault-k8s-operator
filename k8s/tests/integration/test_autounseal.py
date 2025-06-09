import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APPLICATION_NAME,
    AUTOUNSEAL_TOKEN_SECRET_LABEL,
    JUJU_FAST_INTERVAL,
    METADATA,
    NUM_VAULT_UNITS,
)
from tests.integration.helpers import (
    authorize_charm,
    crash_pod,
    deploy_vault,
    get_leader_unit,
    get_model_secret_field,
    get_unit_address,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    initialize_vault_leader,
    revoke_token,
    wait_for_status_message,
)
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)

root_token_vault_b = ""

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APPLICATION_NAME,
        )
        return VaultInit(root_token, key)
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    await ops_test.model.deploy(
        vault_charm_path,
        resources=resources,
        application_name="vault-b",
        trust=True,
        series="noble",
        num_units=1,
        config={"common_name": "example.com"},
    )
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )

    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
        ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
            wait_for_exact_units=1,
        ),
    )

    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    global root_token_vault_b

    await ops_test.model.integrate(
        f"{APPLICATION_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"], status="blocked", wait_for_exact_units=1, idle_period=5
        )

        await wait_for_status_message(
            ops_test=ops_test,
            expected_message="Please initialize Vault",
            app_name="vault-b",
        )

        root_token_vault_b, _ = await initialize_vault_leader(ops_test, "vault-b")
        await wait_for_status_message(
            ops_test=ops_test,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            app_name="vault-b",
        )
        await authorize_charm(ops_test, root_token_vault_b, "vault-b")
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
        )


@pytest.mark.abort_on_fail
async def test_given_vault_b_is_deployed_and_unsealed_when_scale_up_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    app = ops_test.model.applications["vault-b"]
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await app.scale(1)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
        )
        await app.scale(3)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
        )


@pytest.mark.abort_on_fail
async def test_given_vault_b_is_deployed_and_unsealed_when_all_units_crash_then_units_recover(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
        )
    k8s_namespace = ops_test.model.name
    crash_pod(name="vault-b-0", namespace=k8s_namespace)
    crash_pod(name="vault-b-1", namespace=k8s_namespace)
    crash_pod(name="vault-b-2", namespace=k8s_namespace)
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
        )
        leader_unit = await get_leader_unit(ops_test.model, "vault-b")
    leader_unit_address = await get_unit_address(ops_test=ops_test, unit_name=leader_unit.name)
    vault = Vault(
        url=f"https://{leader_unit_address}:8200",
        token=root_token_vault_b,
    )
    await vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
async def test_given_vault_b_is_deployed_and_unsealed_when_auth_token_goes_bad_then_units_recover(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
        )
    auth_token = await get_model_secret_field(
        ops_test=ops_test, label=AUTOUNSEAL_TOKEN_SECRET_LABEL, field="token"
    )
    leader_unit = await get_leader_unit(ops_test.model, "vault-b")
    leader_unit_address = await get_unit_address(ops_test=ops_test, unit_name=leader_unit.name)

    revoke_token(
        token_to_revoke=auth_token,
        root_token=root_token_vault_b,
        endpoint=leader_unit_address,
    )
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
        )
