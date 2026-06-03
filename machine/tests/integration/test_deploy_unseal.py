#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Minimal integration test: deploy Vault and unseal it."""

import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import APP_NAME
from helpers import (
    authorize_charm_and_wait,
    deploy_vault,
    get_leader_unit,
    get_vault_client,
    initialize_vault_leader,
    unseal_all_vault_units,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

JUJU_FAST_INTERVAL = "20s"


@pytest.mark.abort_on_fail
async def test_deploy_and_unseal(ops_test: OpsTest, vault_charm_path: Path):
    """Deploy Vault, initialize, and unseal using self-signed TLS mode."""
    assert ops_test.model
    await deploy_vault(ops_test, num_vaults=1, charm_path=vault_charm_path)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await wait_for_status_message(
            ops_test,
            expected_message="Please initialize Vault or integrate with an auto-unseal provider",
            app_name=APP_NAME,
            timeout=600,
        )

    root_token, unseal_key = await initialize_vault_leader(ops_test, APP_NAME)

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await unseal_all_vault_units(ops_test, unseal_key)

    leader = await get_leader_unit(ops_test.model, APP_NAME)
    vault = await get_vault_client(ops_test, leader, root_token)
    assert not vault.is_sealed(), "Vault should be unsealed"

    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await authorize_charm_and_wait(ops_test, root_token)

    logger.info("Vault deployed, unsealed, and active on s390x")
