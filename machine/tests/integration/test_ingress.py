import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    HAPROXY_APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
)
from helpers import deploy_vault, get_vault_token_and_unseal_key, initialize_unseal_authorize_vault

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APP_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    await ops_test.model.deploy(
        HAPROXY_APPLICATION_NAME,
        channel="2.8/edge",
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME, HAPROXY_APPLICATION_NAME],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


async def test_given_haproxy_deployed_when_integrated_then_status_is_active(
    ops_test: OpsTest,
    deploy: VaultInit,
):
    assert ops_test.model

    haproxy_app = ops_test.model.applications[HAPROXY_APPLICATION_NAME]
    external_hostname = "haproxy"
    await haproxy_app.set_config({"external-hostname": external_hostname})

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{HAPROXY_APPLICATION_NAME}:certificates",
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:ingress",
        relation2=f"{HAPROXY_APPLICATION_NAME}:ingress",
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )
