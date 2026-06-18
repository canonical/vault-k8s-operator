#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Minimal integration test: deploy Vault and unseal it."""

import logging
from pathlib import Path

import jubilant
import pytest

from config import APP_NAME
from helpers import (
    authorize_charm_and_wait,
    deploy_vault,
    fast_forward,
    get_leader_unit_name,
    get_vault_client,
    initialize_vault_leader,
    unseal_all_vault_units,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

JUJU_FAST_INTERVAL = "20s"


@pytest.mark.abort_on_fail
def test_deploy_and_unseal(juju: jubilant.Juju, vault_charm_path: Path):
    """Deploy Vault, initialize, and unseal using self-signed TLS mode."""
    deploy_vault(juju, num_vaults=1, charm_path=vault_charm_path)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        wait_for_status_message(
            juju,
            expected_message="Please initialize Vault or integrate with an auto-unseal provider",
            app_name=APP_NAME,
            timeout=600,
        )

    root_token, unseal_key = initialize_vault_leader(juju, APP_NAME)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, unseal_key)

    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, root_token)
    assert not vault.is_sealed(), "Vault should be unsealed"

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        authorize_charm_and_wait(juju, root_token)

    logger.info("Vault deployed, unsealed, and active on s390x")
