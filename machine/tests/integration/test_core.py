import asyncio
import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    get_ca_cert_file_location,
    get_leader_unit,
    get_leader_unit_address,
    get_vault_client,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)
from vault_helpers import Vault

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool):
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        return
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


@pytest.mark.abort_on_fail
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(  # noqa: E501
    ops_test: OpsTest,
    deploy: None,
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:tls-certificates-access",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
            ops_test.model.wait_for_idle(apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME]),
        )
    vault_ip = await get_leader_unit_address(ops_test.model)
    vault_url = f"https://{vault_ip}:8200"
    ca_file_location = await get_ca_cert_file_location(ops_test)
    assert ca_file_location
    vault = Vault(url=vault_url, ca_file_location=ca_file_location)
    assert not vault.is_initialized()


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest,
    deploy: None,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    ca_file_location = await get_ca_cert_file_location(ops_test)
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    leader = await get_leader_unit(ops_test.model, APP_NAME)

    vault = await get_vault_client(ops_test, leader, root_token, ca_file_location)
    await vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
@pytest.mark.dependency
async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
    ops_test: OpsTest,
    deploy: None,
):
    assert ops_test.model
    root_token, unseal_key = await get_vault_token_and_unseal_key(ops_test.model, APP_NAME)

    num_units = NUM_VAULT_UNITS + 1
    app = ops_test.model.applications[APP_NAME]
    await app.add_unit(count=1)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            wait_for_exact_units=num_units,
        )

    new_unit = app.units[-1]
    vault = await get_vault_client(
        ops_test, new_unit, root_token, await get_ca_cert_file_location(ops_test)
    )
    vault.unseal(unseal_key=unseal_key)
    await vault.wait_for_node_to_be_unsealed()
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=SHORT_TIMEOUT,
            status="active",
        )

    await vault.wait_for_raft_nodes(expected_num_nodes=num_units)


@pytest.mark.abort_on_fail
@pytest.mark.dependency(
    depends=["test_given_application_is_deployed_when_scale_up_then_status_is_active"]
)
async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
    ops_test: OpsTest,
    deploy: None,
):
    assert ops_test.model

    new_unit = ops_test.model.applications[APP_NAME].units[-1]
    await new_unit.remove()
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=SHORT_TIMEOUT,
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    # Note: We are not verifying the number of nodes in the raft cluster
    # because the Vault API address is often not available during the
    # unit removal.
