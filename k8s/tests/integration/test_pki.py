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
    MATCHING_COMMON_NAME,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_CHANNEL,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
    UNMATCHING_COMMON_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_CHANNEL,
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
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)
    deploy_vault(juju, charm_path=vault_charm_path, num_units=NUM_VAULT_UNITS)
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel=SELF_SIGNED_CERTIFICATES_CHANNEL,
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    juju.deploy(
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        channel=VAULT_PKI_REQUIRER_CHANNEL,
        revision=VAULT_PKI_REQUIRER_REVISION,
        config={
            "common_name": f"test.{MATCHING_COMMON_NAME}",
            "sans_dns": f"test.{MATCHING_COMMON_NAME}",
        },
    )

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_blocked(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
                and jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
            ),
            timeout=1000,
        )

    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.config(APPLICATION_NAME, {"pki_ca_common_name": UNMATCHING_COMMON_NAME})
    juju.integrate(
        f"{APPLICATION_NAME}:tls-certificates-pki",
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(
                s, APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME
            ),
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_vault_pki_relation_and_unmatching_common_name_when_integrate_then_cert_not_provided(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APPLICATION_NAME}:vault-pki",
        f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )

    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    leader_address = get_unit_address(juju, leader_name)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        deploy.root_token, leader_address, "charm-pki"
    )
    assert current_issuers_common_name == UNMATCHING_COMMON_NAME

    # jubilant.run() raises TaskError if the action status is 'failed'.
    # The requirer returns a failed status when no certificate is available,
    # so we catch the error and inspect the task results directly.
    try:
        task = juju.run(
            f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0",
            "get-certificate",
            {},
            wait=60,
        )
    except jubilant.TaskError as e:
        task = e.task
    assert task.results.get("certificate") is None


@pytest.mark.abort_on_fail
def test_given_vault_pki_relation_and_matching_common_name_configured_when_integrate_then_cert_is_provided(  # noqa: E501
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.config(
        APPLICATION_NAME,
        {
            "pki_ca_common_name": MATCHING_COMMON_NAME,
            "pki_allow_subdomains": "true",
        },
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
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

    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    leader_address = get_unit_address(juju, leader_name)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        deploy.root_token, leader_address, "charm-pki"
    )
    assert current_issuers_common_name == MATCHING_COMMON_NAME

    task = juju.run(
        f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0",
        "get-certificate",
        {},
        wait=60,
    )
    assert task.results.get("certificate") is not None
    assert task.results.get("ca-certificate") is not None
    assert task.results.get("csr") is not None
