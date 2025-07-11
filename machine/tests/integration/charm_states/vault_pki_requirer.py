from asyncio import Task, create_task

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    MATCHING_COMMON_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_REVISION,
)
from helpers import deploy_if_not_exists


@pytest.fixture(scope="module")
async def vault_pki_requirer_idle(ops_test: OpsTest) -> Task:
    """Deploy the `vault-pki-requirer` charm."""

    async def deploy_pki_requirer(ops_test: OpsTest):
        assert ops_test.model
        config = {
            "common_name": f"test.{MATCHING_COMMON_NAME}",
            "sans_dns": f"test.{MATCHING_COMMON_NAME}",
        }
        await deploy_if_not_exists(
            ops_test.model,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
            config=config,
            revision=VAULT_PKI_REQUIRER_REVISION,
            channel="stable",
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
        )

    return create_task(deploy_pki_requirer(ops_test))
