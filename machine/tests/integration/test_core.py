import asyncio
import logging
from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from tests.integration.helpers import (
    ActionFailedError,
    authorize_charm,
    get_ca_cert_file_location,
    get_leader_unit_address,
    unseal_all_vault_units,
)
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_then_status_blocked(
    ops_test: OpsTest, vault_idle_blocked: Task
):
    assert ops_test.model
    await vault_idle_blocked

    vault_app = ops_test.model.applications[APP_NAME]
    assert vault_app.status == "blocked"


@pytest.mark.abort_on_fail
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(  # noqa: E501
    ops_test: OpsTest, vault_idle_blocked: Task, self_signed_certificates_idle: Task
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    await asyncio.gather(vault_idle_blocked, self_signed_certificates_idle)

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
    vault_initialized: Task,
    self_signed_certificates_idle: Task,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    await self_signed_certificates_idle
    root_token, unseal_key = await vault_initialized
    leader_unit_address = await get_leader_unit_address(ops_test.model)
    ca_file_location = await get_ca_cert_file_location(ops_test)
    vault = Vault(
        url=f"https://{leader_unit_address}:8200",
        ca_file_location=ca_file_location,
        token=root_token,
    )
    assert vault.is_sealed()
    vault.unseal(unseal_key)
    await vault.wait_for_node_to_be_unsealed()
    assert vault.is_active()
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key, ca_file_location)
        try:
            await authorize_charm(ops_test, root_token)
        except ActionFailedError as e:
            logger.warning("Failed to authorize charm: %s", e)
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    await vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
@pytest.mark.dependency
async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
    ops_test: OpsTest,
    vault_unsealed: Task,
):
    assert ops_test.model

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        root_token, unseal_key = await vault_unsealed
    num_units = NUM_VAULT_UNITS + 1
    app = ops_test.model.applications[APP_NAME]
    await app.add_unit(count=1)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            wait_for_exact_units=num_units,
        )

    new_unit = app.units[-1]
    new_unit_address = new_unit.public_address
    vault = Vault(
        url=f"https://{new_unit_address}:8200",
        ca_file_location=await get_ca_cert_file_location(ops_test),
        token=root_token,
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
    vault_authorized: Task,
):
    await vault_authorized
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
