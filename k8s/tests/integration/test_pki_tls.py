# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from pathlib import Path
from typing import Tuple

import pytest
from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    get_vault_pki_intermediate_ca_common_name,
    wait_for_status_message,
)
from tests.integration.integration_support import (
    APPLICATION_NAME,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_REVISION,
    VAULT_PKI_REQUIRER_APPLICATION_NAME,
    VAULT_PKI_REQUIRER_REVISION,
    get_vault_ca_certificate,
    read_vault_unit_statuses,
    run_get_certificate_action,
    unseal_all_vaults,
)


class TestVaultPkiTls:
    """Exercise pkitls behavior."""

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        active_vault: Tuple[int, str, str],
        request: pytest.FixtureRequest,
    ):
        assert ops_test.model
        deploy_self_signed_certificates = ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            channel="1/stable",
            revision=SELF_SIGNED_CERTIFICATES_REVISION,
        )
        pki_requirer_charm_path = request.config.getoption("--pki_requirer_charm_path")

        deploy_vault_pki_requirer = ops_test.model.deploy(
            Path(str(pki_requirer_charm_path)).resolve()
            if pki_requirer_charm_path
            else VAULT_PKI_REQUIRER_APPLICATION_NAME,
            application_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            revision=VAULT_PKI_REQUIRER_REVISION,
            channel="stable",
            config={"common_name": "test.example.com", "sans_dns": "test.example.com"},
        )
        deployed_apps = [
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
        ]
        await asyncio.gather(
            deploy_self_signed_certificates,
            deploy_vault_pki_requirer,
        )
        await ops_test.model.wait_for_idle(
            apps=deployed_apps,
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        vault_app = ops_test.model.applications[APPLICATION_NAME]
        assert vault_app
        common_name = "unmatching-the-requirer.com"
        common_name_config = {
            "common_name": common_name,
        }
        await vault_app.set_config(common_name_config)
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:tls-certificates-pki",
            relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_pki_relation_and_unmatching_common_name_when_integrate_then_cert_not_provided(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-pki",
            relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )
        leader_unit_index, root_token, _ = active_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
            mount="charm-pki",
        )
        assert current_issuers_common_name == "unmatching-the-requirer.com"
        action_output = await run_get_certificate_action(ops_test)
        assert action_output.get("certificate") is None

    @pytest.mark.abort_on_fail
    async def test_given_vault_pki_relation_and_matching_common_name_configured_when_integrate_then_cert_is_provided(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model

        vault_app = ops_test.model.applications[APPLICATION_NAME]
        assert vault_app
        common_name = "example.com"
        common_name_config = {
            "common_name": common_name,
        }
        await vault_app.set_config(common_name_config)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )
        await wait_for_status_message(
            ops_test,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
        )

        leader_unit_index, root_token, _ = active_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
            mount="charm-pki",
        )
        action_output = await run_get_certificate_action(ops_test)
        assert current_issuers_common_name == common_name
        assert action_output["certificate"] is not None
        assert action_output["ca-certificate"] is not None
        assert action_output["csr"] is not None

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_created_then_existing_certificate_replaced(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        assert isinstance(vault_leader_unit, Unit)
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results["stdout"]

        await ops_test.model.integrate(
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{APPLICATION_NAME}:tls-certificates-access",
        )

        await ops_test.model.wait_for_idle(
            apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            timeout=1000,
        )

        final_ca_cert = await get_vault_ca_certificate(vault_leader_unit)
        assert initial_ca_cert != final_ca_cert

        _, root_token, unseal_key = active_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
            )

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_destroyed_then_self_signed_cert_created(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        active_vault: Tuple[int, str, str],
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        assert isinstance(vault_leader_unit, Unit)
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results

        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.remove_relation(
            "tls-certificates-access", f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates"
        )
        await ops_test.model.wait_for_idle(
            apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="blocked",
            timeout=1000,
        )

        final_ca_cert = await get_vault_ca_certificate(vault_leader_unit)
        assert initial_ca_cert != final_ca_cert

        _, root_token, unseal_key = active_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
            )
