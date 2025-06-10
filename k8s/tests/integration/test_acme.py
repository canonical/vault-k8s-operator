import asyncio
import logging
import pdb
from collections import namedtuple
from pathlib import Path

import pytest
import requests
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_CHANNEL,
    SELF_SIGNED_CERTIFICATES_REVISION,
)
from tests.integration.helpers import (
    deploy_vault,
    get_leader_unit,
    get_unit_address,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


async def verify_acme_configured(ops_test: OpsTest, app_name: str) -> bool:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    leader_ip = await get_unit_address(ops_test, leader_unit.name)
    url = f"https://{leader_ip}:8200/v1/charm-acme/acme/directory"

    retry_count = 3
    for attempt in range(retry_count):
        try:
            response = requests.get(url, verify=False)
            if response.status_code == 200 and "newNonce" in response.json():
                return True
            if response.status_code == 403:
                logger.warning("ACME not available yet")
        except (requests.RequestException, ValueError) as e:
            logger.warning("ACME check attempt %s/%s failed: %s", attempt + 1, retry_count, str(e))

        if attempt < retry_count - 1:
            fast_interval_in_seconds = int(JUJU_FAST_INTERVAL[:-1])
            await asyncio.sleep(fast_interval_in_seconds)

    pdb.set_trace()
    return False


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
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel=SELF_SIGNED_CERTIFICATES_CHANNEL,
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            timeout=120,
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
async def test_given_tls_certificates_acme_relation_when_integrate_then_status_is_active_and_acme_configured(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    vault_app = ops_test.model.applications[APPLICATION_NAME]
    common_name = "unmatching-the-requirer.com"
    common_name_config = {
        "common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:tls-certificates-acme",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=60,
        )
        # FIXME: This seems to rely on the reconcile loop -- at least in some
        # cases, so we wait in fast forward
        assert await verify_acme_configured(ops_test, APPLICATION_NAME)
