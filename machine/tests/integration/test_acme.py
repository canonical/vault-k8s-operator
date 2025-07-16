import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
import requests
from juju.application import Application
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    UNMATCHING_COMMON_NAME,
)
from helpers import (
    deploy_vault,
    get_leader,
    get_vault_token_and_unseal_key,
    has_relation,
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

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


async def verify_acme_configured(ops_test: OpsTest, app_name: str) -> bool:
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    url = f"https://{leader_ip}:8200/v1/charm-acme/acme/directory"

    retry_count = 12
    for attempt in range(retry_count):
        try:
            response = requests.get(url, verify=False)
            if response.status_code == 200 and "newNonce" in response.json():
                return True
        except (requests.RequestException, ValueError) as e:
            logger.warning("ACME check attempt %s/%s failed: %s", attempt + 1, retry_count, str(e))

        if attempt < retry_count - 1:
            fast_interval_in_seconds = int(JUJU_FAST_INTERVAL[:-1])
            await asyncio.sleep(fast_interval_in_seconds)

    return False


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_tls_certificates_acme_relation_when_integrate_then_status_is_active_and_acme_configured(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    vault_app = ops_test.model.applications[APP_NAME]
    common_name = UNMATCHING_COMMON_NAME
    common_name_config = {
        "acme_ca_common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
    allow_any_name_config = {
        "acme_allow_any_name": "true",
    }
    await vault_app.set_config(allow_any_name_config)
    allow_subdomains_config = {
        "acme_allow_subdomains": "true",
    }
    await vault_app.set_config(allow_subdomains_config)
    if not has_relation(vault_app, "tls-certificates-acme"):
        await ops_test.model.integrate(
            relation1=f"{APP_NAME}:tls-certificates-acme",
            relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        )
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="active",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
            ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
                status="active",
                wait_for_exact_units=1,  # self-signed certificates app
            ),
        )
        # FIXME: This seems to rely on the reconcile loop -- at least in some
        # cases, so we wait in fast forward
        # https://warthogs.atlassian.net/browse/TLSENG-766
        assert await verify_acme_configured(ops_test, APP_NAME)
