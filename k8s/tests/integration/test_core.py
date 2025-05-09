
import logging
from asyncio import Task
from typing import Tuple

import hvac
import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from tests.integration.config import APPLICATION_NAME, JUJU_FAST_INTERVAL, NUM_VAULT_UNITS
from tests.integration.helpers import (
    ActionFailedError,
    authorize_charm,
    crash_pod,
    get_ca_cert_file_location,
    get_leader_unit_address,
    read_vault_unit_statuses,
    unseal_all_vault_units,
    wait_for_status_message,
)
from tests.integration.vault import Vault

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_given_vault_deployed_and_initialized_when_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest, vault_initialized: Task[Tuple[str, str]]
):
    # assert ops_test.model
    # leader_unit_index, root_token, unseal_key = await vault_initialized
    # unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
    # async with ops_test.fast_forward(fast_interval="60s"):
    #     unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
    #     await wait_for_status_message(
    #         ops_test=ops_test,
    #         expected_message="Please authorize charm (see `authorize-charm` action)",
    #     )
    #     unseal_all_vaults(unit_addresses, root_token, unseal_key)
    #     await wait_for_status_message(
    #         ops_test=ops_test,
    #         expected_message="Please authorize charm (see `authorize-charm` action)",
    #         unit_name=f"{APPLICATION_NAME}/{leader_unit_index}",
    #     )
    #     await authorize_charm(ops_test, root_token)
    #     await ops_test.model.wait_for_idle(
    #         apps=[APPLICATION_NAME],
    #         status="active",
    #         timeout=1000,
    #         wait_for_exact_units=NUM_VAULT_UNITS,
    #     )

    assert ops_test.model
    root_token, unseal_key = await vault_initialized
    leader_unit_address = await get_leader_unit_address(ops_test)
    vault = Vault(
        url=f"https://{leader_unit_address}:8200",
        token=root_token,
    )
    assert vault.is_sealed()
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key)
        try:
            await authorize_charm(ops_test, root_token)
        except ActionFailedError as e:
            logger.warning("Failed to authorize charm: %s", e)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    await vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)

# @pytest.mark.abort_on_fail
# async def test_given_application_is_deployed_when_pod_crashes_then_unit_recovers(
#     ops_test: OpsTest,
#     vault_initialized: Task,
# ):
#     assert ops_test.model
#     _, root_token, unseal_key = await vault_initialized
#     crashing_pod_index = 1
#     k8s_namespace = ops_test.model.name
#     crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
#     await wait_for_status_message(
#         ops_test, expected_message="Please unseal Vault", timeout=300
#     )
#     unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
#     unseal_vault(unit_addresses[crashing_pod_index], root_token, unseal_key)
#     async with ops_test.fast_forward(fast_interval="60s"):
#         await ops_test.model.wait_for_idle(
#             apps=[APPLICATION_NAME],
#             status="active",
#             timeout=1000,
#             wait_for_exact_units=NUM_VAULT_UNITS,
#         )

# @pytest.mark.abort_on_fail
# async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
#     ops_test: OpsTest,
#     vault_initialized: Task,
# ):
#     assert ops_test.model
#     _, root_token, unseal_key = await vault_initialized
#     num_units = NUM_VAULT_UNITS + 1
#     app = ops_test.model.applications[APPLICATION_NAME]
#     assert isinstance(app, Application)
#     await app.scale(num_units)

#     await wait_for_status_message(
#         ops_test, expected_message="Please unseal Vault", timeout=300
#     )
#     unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
#     unseal_vault(unit_addresses[-1], root_token, unseal_key)

#     async with ops_test.fast_forward(fast_interval="60s"):
#         await ops_test.model.wait_for_idle(
#             apps=[APPLICATION_NAME],
#             status="active",
#             timeout=1000,
#             wait_for_exact_units=num_units,
#         )

# @pytest.mark.abort_on_fail
# async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
#     ops_test: OpsTest,
#     vault_initialized: Task,
# ):
#     assert ops_test.model
#     _, root_token, _ = await vault_initialized
#     app = ops_test.model.applications[APPLICATION_NAME]
#     assert isinstance(app, Application)

#     unit_addresses = [row.get("address") for row in await read_vault_unit_statuses(ops_test)]
#     client = hvac.Client(url=f"https://{unit_addresses[-1]}:8200", verify=False)
#     client.token = root_token
#     response = client.sys.read_raft_config()
#     assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS + 1

#     await app.scale(NUM_VAULT_UNITS)
#     await ops_test.model.wait_for_idle(
#         apps=[APPLICATION_NAME],
#         status="active",
#         timeout=1000,
#         wait_for_exact_units=NUM_VAULT_UNITS,
#     )

#     unit_addresses = [row.get("address") for row in await read_vault_unit_statuses(ops_test)]
#     client = hvac.Client(url=f"https://{unit_addresses[0]}:8200", verify=False)
#     client.token = root_token
#     response = client.sys.read_raft_config()
#     assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS
