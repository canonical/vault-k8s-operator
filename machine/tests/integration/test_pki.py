import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    MATCHING_COMMON_NAME,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
    UNMATCHING_COMMON_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_REVISION,
)
from helpers import (
    deploy_vault,
    fast_forward,
    get_leader_unit_address,
    get_vault_pki_intermediate_ca_common_name,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    run_get_certificate_action,
    wait_for_certificate_to_be_provided,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APP_NAME)
        return VaultInit(root_token, key)
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    juju.deploy(
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        channel="latest/stable",
        revision=VAULT_PKI_REQUIRER_REVISION,
        config={
            "common_name": f"test.{MATCHING_COMMON_NAME}",
            "sans_dns": f"test.{MATCHING_COMMON_NAME}",
        },
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
                and jubilant.all_blocked(s, APP_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1000,
        )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    # Set the configuration, necessary for the charm to go active.
    common_name_config = {
        "pki_ca_common_name": UNMATCHING_COMMON_NAME,
        "pki_ca_sans_dns": UNMATCHING_COMMON_NAME,
        "pki_allow_subdomains": "true",
    }
    juju.config(APP_NAME, common_name_config)

    juju.integrate(
        f"{APP_NAME}:tls-certificates-pki",
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME)
                and jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_vault_pki_relation_and_unmatching_common_name_when_integrate_then_cert_not_provided(  # noqa: E501
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    juju.integrate(
        f"{APP_NAME}:vault-pki",
        f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME)
                and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )

    leader_unit_address = get_leader_unit_address(juju)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        unit_address=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == UNMATCHING_COMMON_NAME

    try:
        action_output = run_get_certificate_action(juju)
    except jubilant.TaskError as e:
        action_output = e.task.results
    assert action_output.get("certificate") is None


@pytest.mark.abort_on_fail
def test_given_vault_pki_relation_and_matching_common_name_configured_when_integrate_then_cert_is_provided(  # noqa: E501
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    common_name_config = {
        "pki_ca_common_name": MATCHING_COMMON_NAME,
        "pki_ca_sans_dns": MATCHING_COMMON_NAME,
        "pki_allow_subdomains": "true",
    }
    juju.config(APP_NAME, common_name_config)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME)
                and jubilant.all_active(s, VAULT_PKI_REQUIRER_APPLICATION_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
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

    leader_unit_address = get_leader_unit_address(juju)
    assert leader_unit_address
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        unit_address=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == MATCHING_COMMON_NAME

    wait_for_certificate_to_be_provided(juju)
    action_output = run_get_certificate_action(juju)
    assert action_output.get("certificate", None) is not None
    assert action_output.get("ca-certificate", None) is not None
    assert action_output.get("csr", None) is not None
