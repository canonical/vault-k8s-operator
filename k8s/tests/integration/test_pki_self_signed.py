#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for PKI self-signed CA functionality.

This module tests the PKI feature when Vault uses its own self-signed CA
instead of relying on an external CA provider via the tls-certificates-pki relation.
"""

import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_REVISION,
)
from helpers import (
    deploy_vault,
    get_leader_unit,
    get_unit_address,
    get_vault_pki_intermediate_ca_common_name,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
async def deploy(
    ops_test: OpsTest, vault_charm_path: Path, pki_requirer_charm_path: Path, skip_deploy: bool
) -> VaultInit:
    """Build and deploy the application without external CA.

    This fixture deploys Vault and the PKI requirer charm, but deliberately
    does NOT deploy the self-signed-certificates charm. This tests the
    self-signed CA functionality where Vault generates its own CA.
    """
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
        pki_requirer_charm_path
        if pki_requirer_charm_path
        else VAULT_PKI_REQUIRER_APPLICATION_NAME,
        application_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
        revision=VAULT_PKI_REQUIRER_REVISION,
        channel="stable",
        config={"common_name": "test.example.com", "sans_dns": "test.example.com"},
    )
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
        ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
        ),
    )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
async def test_given_no_external_ca_and_common_name_configured_when_integrate_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    """Test that Vault becomes active when PKI is configured without external CA."""
    assert ops_test.model

    vault_app = ops_test.model.applications[APPLICATION_NAME]
    common_name = "self-signed-ca.example.com"
    await vault_app.set_config(
        {
            "pki_ca_common_name": common_name,
        }
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
async def test_given_self_signed_ca_configured_when_integrate_vault_pki_then_certificate_is_issued(
    ops_test: OpsTest, deploy: VaultInit
):
    """Test that certificates are issued using the self-signed CA."""
    assert ops_test.model

    vault_app = ops_test.model.applications[APPLICATION_NAME]
    common_name = "example.com"
    await vault_app.set_config(
        {
            "pki_ca_common_name": common_name,
            "pki_allow_subdomains": "true",
        }
    )
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:vault-pki",
        relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=SHORT_TIMEOUT,
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
            ops_test.model.wait_for_idle(
                apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
                status="active",
                timeout=SHORT_TIMEOUT,
                wait_for_exact_units=1,
            ),
        )
        await wait_for_status_message(
            ops_test,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
            timeout=SHORT_TIMEOUT,
        )

    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    leader_unit_address = await get_unit_address(ops_test, leader_unit.name)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == common_name

    action_output = await run_get_certificate_action(ops_test)
    assert action_output["certificate"] is not None
    assert action_output["ca-certificate"] is not None
    assert action_output["csr"] is not None


@pytest.mark.abort_on_fail
async def test_given_self_signed_ca_when_common_name_changed_then_new_ca_is_generated(
    ops_test: OpsTest, deploy: VaultInit
):
    """Test that changing pki_ca_common_name regenerates the self-signed CA."""
    assert ops_test.model

    vault_app = ops_test.model.applications[APPLICATION_NAME]
    new_common_name = "rotated-ca.example.com"

    # First verify the current CA common name
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    leader_unit_address = await get_unit_address(ops_test, leader_unit.name)
    old_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )

    # Change the common name
    await vault_app.set_config(
        {
            "pki_ca_common_name": new_common_name,
            "pki_allow_subdomains": "true",
        }
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=SHORT_TIMEOUT,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        # Wait for the requirer to receive a new certificate
        await wait_for_status_message(
            ops_test,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
            timeout=SHORT_TIMEOUT,
        )

    # Verify the CA common name has changed
    current_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )
    assert current_common_name == new_common_name
    assert current_common_name != old_common_name


async def run_get_certificate_action(ops_test: OpsTest) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output
