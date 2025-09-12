import asyncio
import logging
from collections import namedtuple
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

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
async def deploy(ops_test: OpsTest, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    assert ops_test.model
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = await get_vault_token_and_unseal_key(
            ops_test.model,
            APP_NAME,
        )
        return VaultInit(root_token, key)
    await deploy_vault(
        ops_test,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    await ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    await ops_test.model.deploy(
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
    async with ops_test.fast_forward(JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[
                    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
                    VAULT_PKI_REQUIRER_APPLICATION_NAME,
                ],
            ),
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="blocked",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
        )
    root_token, unseal_key = await initialize_unseal_authorize_vault(ops_test, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    ops_test: OpsTest, deploy: VaultInit
):
    assert ops_test.model

    # Set the configuration, necessary for the charm to go active.
    common_name_config = {
        "pki_ca_common_name": UNMATCHING_COMMON_NAME,
        "pki_ca_sans_dns": UNMATCHING_COMMON_NAME,
        "pki_allow_subdomains": "true",
    }
    vault_app = ops_test.model.applications[APP_NAME]
    await vault_app.set_config(common_name_config)

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:tls-certificates-pki",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="active",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
            ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
                status="active",
                wait_for_exact_units=1,
            ),
        )


@pytest.mark.abort_on_fail
@pytest.mark.dependency(
    depends=["test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active"]
)
async def test_given_vault_pki_relation_and_unmatching_common_name_when_integrate_then_cert_not_provided(  # noqa: E501
    ops_test: OpsTest,
    deploy: VaultInit,
):
    assert ops_test.model

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:vault-pki",
        relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
    )
    async with ops_test.fast_forward(fast_interval=JUJU_FAST_INTERVAL):
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[APP_NAME],
                status="active",
                wait_for_exact_units=NUM_VAULT_UNITS,
            ),
            ops_test.model.wait_for_idle(
                apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
                status="active",
                wait_for_exact_units=1,
            ),
        )

    leader_unit_address = await get_leader_unit_address(ops_test.model)
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        unit_address=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == UNMATCHING_COMMON_NAME

    action_output = await run_get_certificate_action(ops_test)
    assert action_output.get("certificate") is None


@pytest.mark.abort_on_fail
@pytest.mark.dependency(
    depends=["test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active"]
)
async def test_given_vault_pki_relation_and_matching_common_name_configured_when_integrate_then_cert_is_provided(  # noqa: E501
    ops_test: OpsTest,
    deploy: VaultInit,
):
    assert ops_test.model

    vault_app = ops_test.model.applications[APP_NAME]
    common_name_config = {
        "pki_ca_common_name": MATCHING_COMMON_NAME,
        "pki_ca_sans_dns": MATCHING_COMMON_NAME,
        "pki_allow_subdomains": "true",
    }
    await vault_app.set_config(common_name_config)
    await asyncio.gather(
        ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
        ),
        ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
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

    leader_unit_address = await get_leader_unit_address(ops_test.model)
    assert leader_unit_address
    current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
        root_token=deploy.root_token,
        unit_address=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == MATCHING_COMMON_NAME

    await wait_for_certificate_to_be_provided(ops_test)
    action_output = await run_get_certificate_action(ops_test)
    assert action_output.get("certificate", None) is not None
    assert action_output.get("ca-certificate", None) is not None
    assert action_output.get("csr", None) is not None
