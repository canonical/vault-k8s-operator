import asyncio
from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    MATCHING_COMMON_NAME,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
    UNMATCHING_COMMON_NAME,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
)
from tests.integration.helpers import (
    get_leader_unit_address,
    get_vault_pki_intermediate_ca_common_name,
    has_relation,
    run_get_certificate_action,
    wait_for_certificate_to_be_provided,
    wait_for_status_message,
)


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, self_signed_certificates_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await self_signed_certificates_idle

    vault_app = ops_test.model.applications[APP_NAME]
    common_name = UNMATCHING_COMMON_NAME
    common_name_config = {
        "common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
    if not has_relation(vault_app, "tls-certificates-pki"):
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
    vault_authorized: Task,
    vault_pki_requirer_idle: Task,
):
    assert ops_test.model
    root_token, _ = await vault_authorized
    await vault_pki_requirer_idle

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
        root_token=root_token,
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
    vault_authorized: Task,
    vault_pki_requirer_idle: Task,
):
    assert ops_test.model
    root_token, _ = await vault_authorized
    await vault_pki_requirer_idle

    vault_app = ops_test.model.applications[APP_NAME]
    common_name = MATCHING_COMMON_NAME
    common_name_config = {
        "common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
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
        root_token=root_token,
        unit_address=leader_unit_address,
        mount="charm-pki",
    )
    assert current_issuers_common_name == common_name

    await wait_for_certificate_to_be_provided(ops_test)
    action_output = await run_get_certificate_action(ops_test)
    assert action_output.get("certificate", None) is not None
    assert action_output.get("ca-certificate", None) is not None
    assert action_output.get("csr", None) is not None
