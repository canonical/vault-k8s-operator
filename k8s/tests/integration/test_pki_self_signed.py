# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

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
    fast_forward,
    get_leader_unit_name,
    get_unit_address,
    get_vault_pki_intermediate_ca_common_name,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(
    juju: jubilant.Juju,
    vault_charm_path: Path,
    pki_requirer_charm_path: Path,
    skip_deploy: bool,
) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)

    deploy_vault(juju, charm_path=vault_charm_path, num_units=NUM_VAULT_UNITS)
    juju.deploy(
        pki_requirer_charm_path
        if pki_requirer_charm_path
        else VAULT_PKI_REQUIRER_APPLICATION_NAME,
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        revision=VAULT_PKI_REQUIRER_REVISION,
        channel="stable",
        config={"common_name": "test.example.com", "sans_dns": "test.example.com"},
    )
    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
        ),
    )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_no_external_ca_and_common_name_configured_when_integrate_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    """Test that Vault becomes active when PKI is configured without external CA."""
    common_name = "self-signed-ca.example.com"
    juju.config(APPLICATION_NAME, {"pki_ca_common_name": common_name})
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, APPLICATION_NAME),
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_self_signed_ca_configured_when_integrate_vault_pki_then_certificate_is_issued(
    juju: jubilant.Juju, deploy: VaultInit
):
    """Test that certificates are issued using the self-signed CA."""
    common_name = "example.com"
    juju.config(
        APPLICATION_NAME,
        {"pki_ca_common_name": common_name, "pki_allow_subdomains": "true"},
    )
    juju.integrate(
        f"{APPLICATION_NAME}:vault-pki",
        f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME, VAULT_PKI_REQUIRER_APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
                and len(s.apps[VAULT_PKI_REQUIRER_APPLICATION_NAME].units) == 1
            ),
            timeout=SHORT_TIMEOUT,
        )
        wait_for_status_message(
            juju,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
            timeout=SHORT_TIMEOUT,
        )

    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    leader_unit_address = get_unit_address(juju, leader_name)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == common_name

    task = juju.run(f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0", "get-certificate", {}, wait=240)
    assert task.results.get("certificate") is not None
    assert task.results.get("ca-certificate") is not None
    assert task.results.get("csr") is not None


@pytest.mark.abort_on_fail
def test_given_self_signed_ca_when_common_name_changed_then_new_ca_is_generated(
    juju: jubilant.Juju, deploy: VaultInit
):
    """Test that changing pki_ca_common_name regenerates the self-signed CA."""
    new_common_name = "rotated-ca.example.com"

    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    leader_unit_address = get_unit_address(juju, leader_name)
    old_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )

    juju.config(
        APPLICATION_NAME,
        {"pki_ca_common_name": new_common_name, "pki_allow_subdomains": "true"},
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
        wait_for_status_message(
            juju,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
            timeout=SHORT_TIMEOUT,
        )

    current_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        endpoint=leader_unit_address,
        mount="charm-pki",
    )
    assert current_common_name == new_common_name
    assert current_common_name != old_common_name
