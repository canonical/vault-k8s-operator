#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Minimal integration test: deploy Vault K8s and unseal it."""

import logging
from pathlib import Path

import jubilant
import pytest

from config import APPLICATION_NAME, JUJU_FAST_INTERVAL
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


@pytest.mark.abort_on_fail
def test_deploy_and_unseal(juju: jubilant.Juju, vault_charm_path: Path):
    """Deploy Vault K8s, initialize, and unseal."""
    deploy_vault(juju, num_units=1, charm_path=vault_charm_path)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        wait_for_status_message(
            juju,
            expected_message="Please initialize Vault or integrate with an auto-unseal provider",
            app_name=APPLICATION_NAME,
            timeout=600,
        )

    root_token, unseal_key = initialize_vault_leader(juju, APPLICATION_NAME)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, unseal_key, root_token)

    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    vault = get_vault_client(juju, leader_name, root_token)
    assert not vault.is_sealed(), "Vault should be unsealed"

    authorize_charm_and_wait(juju, root_token)

    logger.info("Vault K8s deployed, unsealed, and active on s390x")
