import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APPLICATION_NAME,
    LOKI_APPLICATION_NAME,
    NUM_VAULT_UNITS,
    PROMETHEUS_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

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
            APPLICATION_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        PROMETHEUS_APPLICATION_NAME,
        application_name=PROMETHEUS_APPLICATION_NAME,
        trust=True,
        channel="1/stable",
    )
    await ops_test.model.deploy(
        LOKI_APPLICATION_NAME,
        application_name=LOKI_APPLICATION_NAME,
        trust=True,
        channel="1/stable",
    )
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[PROMETHEUS_APPLICATION_NAME, LOKI_APPLICATION_NAME],
            raise_on_error=False,  # Prometheus-k8s can fail on deploy sometimes
        ),
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
    )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:metrics-endpoint",
        relation2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME, PROMETHEUS_APPLICATION_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_given_loki_deployed_when_relate_vault_to_loki_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:logging",
        relation2=f"{LOKI_APPLICATION_NAME}",
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME, LOKI_APPLICATION_NAME],
        status="active",
        timeout=SHORT_TIMEOUT,
    )
