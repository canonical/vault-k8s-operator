#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import hvac
import pytest
import yaml
from cryptography import x509
from juju.action import Action
from juju.application import Application
from juju.unit import Unit
from pytest import FixtureRequest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    crash_pod,
    get_leader_unit,
    get_model_secret_field,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_KV_REQUIRER_1_APPLICATION_NAME = "vault-kv-requirer-a"
VAULT_KV_REQUIRER_2_APPLICATION_NAME = "vault-kv-requirer-b"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
VAULT_PKI_REQUIRER_REVISION = 93
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
MINIO_APPLICATION_NAME = "minio"
AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
MINIO_CONFIG = {
    "access-key": MINIO_S3_ACCESS_KEY,
    "secret-key": MINIO_S3_SECRET_KEY,
}

NUM_VAULT_UNITS = 3


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


@pytest.fixture(scope="module")
async def deployed_vault(ops_test: OpsTest, request: pytest.FixtureRequest):
    """Deploy Vault."""
    assert ops_test.model
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
    await ops_test.model.deploy(
        charm_path,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
        series="jammy",
        num_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )


@pytest.fixture(scope="module")
async def deployed_vault_initialized_leader(
    ops_test: OpsTest, deployed_vault: Dict[str, Path | str]
) -> Tuple[int, str, str]:
    return await initialize_vault_leader(ops_test, APPLICATION_NAME)


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[int, str, str]:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    leader_unit_index = int(leader_unit.name.split("/")[-1])
    unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test, app_name)]
    client = hvac.Client(url=f"https://{unit_addresses[leader_unit_index]}:8200", verify=False)
    seal_type = client.seal_status["type"]  # type: ignore -- bad type hints in stubs
    if seal_type == "shamir":
        initialize_response = client.sys.initialize(secret_shares=1, secret_threshold=1)
        root_token, unseal_key = initialize_response["root_token"], initialize_response["keys"][0]
        await ops_test.model.add_secret(
            "initialization-secrets", [f"root-token={root_token}", f"unseal-key={unseal_key}"]
        )
        return leader_unit_index, root_token, unseal_key
    initialize_response = client.sys.initialize(recovery_shares=1, recovery_threshold=1)
    root_token, recovery_key = (
        initialize_response["root_token"],
        initialize_response["recovery_keys"][0],
    )
    # Add the token/key to the model so they can be retrieved later if we need to debug
    await ops_test.model.add_secret(
        f"initialization-secrets-{app_name}",
        [f"root-token={root_token}", f"recovery-key={recovery_key}"],
    )
    return leader_unit_index, root_token, recovery_key


class TestVaultK8s:
    """This test class tests vault's deployment and activation."""

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_and_initialized_when_unsealed_and_authorized_then_status_is_active(
        self, ops_test: OpsTest, deployed_vault_initialized_leader: Tuple[int, str, str]
    ):
        assert ops_test.model
        leader_unit_index, root_token, unseal_key = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        async with ops_test.fast_forward(fast_interval="60s"):
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
            )
            unseal_all_vaults(unit_addresses, root_token, unseal_key)
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                count=NUM_VAULT_UNITS,
            )
            await authorize_charm(ops_test, root_token)
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_pod_crashes_then_unit_recovers(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = deployed_vault_initialized_leader
        crashing_pod_index = 1
        k8s_namespace = ops_test.model.name
        crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
        await wait_for_status_message(
            ops_test, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[crashing_pod_index], root_token, unseal_key)
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
                wait_for_exact_units=NUM_VAULT_UNITS,
            )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = deployed_vault_initialized_leader
        num_units = NUM_VAULT_UNITS + 1
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.scale(num_units)

        await wait_for_status_message(
            ops_test, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[-1], root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
                wait_for_exact_units=num_units,
            )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, _ = deployed_vault_initialized_leader
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)

        unit_addresses = [row.get("address") for row in await read_vault_unit_statuses(ops_test)]
        client = hvac.Client(url=f"https://{unit_addresses[-1]}:8200", verify=False)
        client.token = root_token
        response = client.sys.read_raft_config()
        assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS + 1

        await app.scale(NUM_VAULT_UNITS)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        client = hvac.Client(url=f"https://{unit_addresses[0]}:8200", verify=False)
        client.token = root_token
        response = client.sys.read_raft_config()
        assert len(response["data"]["config"]["servers"]) == NUM_VAULT_UNITS


class TestVaultK8sIntegrationsPart1:
    """Test some of the integrations and the related actions between Vault and its relations.

    The relations under test are:
        providing:
            vault-kv x 2,
            vault-pki,
            send-ca-cert
        requiring:
            ingress,
            tls-certificates-access,
            tls-certificates-pki,
    """

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
        request: pytest.FixtureRequest,
    ):
        assert ops_test.model
        kv_requirer_charm_path = Path(
            str(request.config.getoption("--kv_requirer_charm_path"))
        ).resolve()
        deploy_self_signed_certificates = ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            channel="edge",
        )
        deploy_vault_kv_requirer_1 = ops_test.model.deploy(
            kv_requirer_charm_path,
            application_name=VAULT_KV_REQUIRER_1_APPLICATION_NAME,
            num_units=1,
        )
        deploy_vault_kv_requirer_2 = ops_test.model.deploy(
            kv_requirer_charm_path,
            application_name=VAULT_KV_REQUIRER_2_APPLICATION_NAME,
            num_units=1,
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
            VAULT_KV_REQUIRER_1_APPLICATION_NAME,
            VAULT_KV_REQUIRER_2_APPLICATION_NAME,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
        ]
        await asyncio.gather(
            deploy_self_signed_certificates,
            deploy_vault_pki_requirer,
            deploy_vault_kv_requirer_1,
            deploy_vault_kv_requirer_2,
        )
        await ops_test.model.wait_for_idle(
            apps=deployed_apps,
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        _, root_token, unseal_key = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)
        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        secret_key = "test-key"
        secret_value = "test-value"
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_related_and_requirer_pod_crashes_when_create_secret_then_secret_is_created(  # noqa: E501
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        secret_key = "test-key"
        secret_value = "test-value"
        assert ops_test.model
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_1_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        k8s_namespace = ops_test.model.name

        crash_pod(
            name=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}-0",
            namespace=k8s_namespace,
        )

        await ops_test.model.wait_for_idle(
            apps=[VAULT_KV_REQUIRER_1_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value

    @pytest.mark.abort_on_fail
    async def test_given_multiple_kv_requirers_related_when_secrets_created_then_secrets_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_2_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        secret_key = "test-key-2"
        secret_value = "test-value-2"
        assert ops_test.model
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_2_APPLICATION_NAME]
        assert isinstance(vault_kv_application, Application)
        vault_kv_unit = vault_kv_application.units[0]
        vault_kv_create_secret_action = await vault_kv_unit.run_action(
            action_name="create-secret",
            key=secret_key,
            value=secret_value,
        )

        await ops_test.model.get_action_output(
            action_uuid=vault_kv_create_secret_action.entity_id, wait=30
        )

        vault_kv_get_secret_action = await vault_kv_unit.run_action(
            action_name="get-secret",
            key=secret_key,
        )

        action_output = await ops_test.model.get_action_output(
            action_uuid=vault_kv_get_secret_action.entity_id, wait=30
        )

        assert action_output["value"] == secret_value

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
        deployed_vault_initialized_leader: Tuple[int, str, str],
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
        leader_unit_index, root_token, _ = deployed_vault_initialized_leader
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
        deployed_vault_initialized_leader: Tuple[int, str, str],
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

        leader_unit_index, root_token, _ = deployed_vault_initialized_leader
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
        deployed_vault_initialized_leader: Tuple[int, str, str],
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

        _, root_token, unseal_key = deployed_vault_initialized_leader
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
        deployed_vault_initialized_leader: Tuple[int, str, str],
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

        _, root_token, unseal_key = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[APPLICATION_NAME],
                status="active",
                timeout=1000,
            )


class TestVaultK8sIntegrationsPart2:
    """Test some of the integrations and the related actions between Vault and its relations.

    The relations under test are:
        providing:
            metrics-endpoint
        requiring:
            logging,
            s3-parameters
    """

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
    ):
        assert ops_test.model
        deploy_prometheus = ops_test.model.deploy(
            "prometheus-k8s",
            application_name=PROMETHEUS_APPLICATION_NAME,
            trust=True,
        )
        deploy_loki = ops_test.model.deploy(
            "loki-k8s",
            application_name=LOKI_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
        deploy_s3_integrator = ops_test.model.deploy(
            "s3-integrator",
            application_name=S3_INTEGRATOR_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
        deploy_minio = ops_test.model.deploy(
            "minio",
            application_name=MINIO_APPLICATION_NAME,
            trust=True,
            config=MINIO_CONFIG,
            channel="ckf-1.9/stable",
        )
        await asyncio.gather(
            deploy_prometheus,
            deploy_loki,
            deploy_s3_integrator,
            deploy_minio,
        )
        deployed_apps = [
            PROMETHEUS_APPLICATION_NAME,
            LOKI_APPLICATION_NAME,
            S3_INTEGRATOR_APPLICATION_NAME,
            MINIO_APPLICATION_NAME,
        ]
        await ops_test.model.wait_for_idle(
            apps=[app for app in deployed_apps if app != S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=600,
            wait_for_at_least_units=1,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

        _, root_token, unseal_key = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)
        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_related_to_s3_integrator_when_create_backup_action_then_backup_is_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[MINIO_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )
        status = await ops_test.model.get_status()
        minio_app = status.applications[MINIO_APPLICATION_NAME]
        assert minio_app
        minio_unit = minio_app.units[f"{MINIO_APPLICATION_NAME}/0"]
        assert minio_unit
        minio_ip = minio_unit.address
        endpoint = f"http://{minio_ip}:9000"
        s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
        assert s3_integrator
        await run_s3_integrator_sync_credentials_action(
            ops_test,
            secret_key=MINIO_S3_SECRET_KEY,
            access_key=MINIO_S3_ACCESS_KEY,
        )
        s3_config = {
            "endpoint": endpoint,
            "bucket": "test-bucket",
            "region": "local",
        }
        await s3_integrator.set_config(s3_config)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.integrate(
            relation1=APPLICATION_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        create_backup_action_output = await run_create_backup_action(ops_test)
        assert create_backup_action_output["backup-id"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_list_backups_action_then_backups_are_listed(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await run_list_backups_action(ops_test)
        assert list_backups_action_output["backup-ids"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_restore_backup_action_then_backup_is_restored(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await run_list_backups_action(ops_test)
        backup_id = json.loads(list_backups_action_output["backup-ids"])[0]
        # In this test we are not using the correct unsealed keys and root token.
        restore_backup_action_output = await run_restore_backup_action(
            ops_test, backup_id=backup_id
        )
        assert restore_backup_action_output.get("return-code") == 0
        assert not restore_backup_action_output.get("stderr", None)
        assert restore_backup_action_output.get("restored", None) == backup_id

    @pytest.mark.abort_on_fail
    async def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:metrics-endpoint",
            relation2=f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_loki_deployed_when_relate_vault_to_loki_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:logging",
            relation2=f"{LOKI_APPLICATION_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, LOKI_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )


class TestVaultK8sIntegrationsPart3:
    """Test some of the integrations and the related actions between Vault and its relations.

    The relations under test are:
        providing:
            vault-autounseal
        requiring:
            logging,
            vault-autounseal
    """

    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self,
        ops_test: OpsTest,
        deployed_vault_initialized_leader: Tuple[int, str, str],
        request: FixtureRequest,
    ):
        assert ops_test.model
        resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
        charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()
        await ops_test.model.deploy(
            charm_path,
            resources=resources,
            application_name="vault-b",
            trust=True,
            series="jammy",
            num_units=1,
            config={"common_name": "example.com"},
        )
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

        leader_unit_index, root_token, unseal_key = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(unit_addresses, root_token, unseal_key)
        yield
        await ops_test.model.remove_application(app_name="vault-b")

    @pytest.mark.abort_on_fail
    async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        await ops_test.model.integrate(
            f"{APPLICATION_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=["vault-b"], status="blocked", wait_for_exact_units=1, idle_period=5
            )

            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please initialize Vault",
                app_name="vault-b",
            )

            leader_unit_index, root_token, recovery_key = await initialize_vault_leader(
                ops_test, "vault-b"
            )
            await wait_for_status_message(
                ops_test=ops_test,
                expected_message="Please authorize charm (see `authorize-charm` action)",
                app_name="vault-b",
            )
            await authorize_charm(ops_test, root_token, "vault-b")
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=1,
                idle_period=5,
            )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_scale_up_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await app.scale(1)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
            idle_period=5,
        )
        await app.scale(3)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_all_units_crash_then_units_recover(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )
        k8s_namespace = ops_test.model.name
        crash_pod(name="vault-b-0", namespace=k8s_namespace)
        crash_pod(name="vault-b-1", namespace=k8s_namespace)
        crash_pod(name="vault-b-2", namespace=k8s_namespace)
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=3,
                idle_period=5,
            )

    @pytest.mark.abort_on_fail
    async def test_given_vault_b_is_deployed_and_unsealed_when_auth_token_goes_bad_then_units_recover(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        deployed_vault_initialized_leader: Tuple[int, str, str],
    ):
        assert ops_test.model

        app = ops_test.model.applications["vault-b"]
        assert isinstance(app, Application)
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=3,
            idle_period=5,
        )
        auth_token = await get_model_secret_field(
            ops_test=ops_test, label=AUTOUNSEAL_TOKEN_SECRET_LABEL, field="token"
        )
        leader_unit_index, root_token, _ = deployed_vault_initialized_leader
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        revoke_token(
            token_to_revoke=auth_token,
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
        )
        async with ops_test.fast_forward():
            await ops_test.model.wait_for_idle(
                apps=["vault-b"],
                status="active",
                wait_for_exact_units=3,
                idle_period=5,
            )


async def run_get_certificate_action(ops_test: OpsTest) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    assert isinstance(tls_requirer_unit, Unit)
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    assert isinstance(action, Action)
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output


async def run_get_ca_certificate_action(ops_test: OpsTest, timeout: int = 60) -> dict:
    """Run the `get-certificate` on the `vault-k8s` unit.

    Args:
        ops_test (OpsTest): OpsTest
        timeout (int, optional): Timeout in seconds. Defaults to 60.

    Returns:
        dict: Action output
    """
    assert ops_test.model
    self_signed_certificates_unit = ops_test.model.units[
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0"
    ]
    assert isinstance(self_signed_certificates_unit, Unit)
    action = await self_signed_certificates_unit.run_action(
        action_name="get-ca-certificate",
    )
    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)


async def get_vault_ca_certificate(vault_unit: Unit) -> str:
    action = await vault_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
    await action.wait()
    return action.results["stdout"]


async def run_s3_integrator_sync_credentials_action(
    ops_test: OpsTest, access_key: str, secret_key: str
) -> dict:
    """Run the `sync-s3-credentials` action on the `s3-integrator` leader unit.

    Args:
        ops_test (OpsTest): OpsTest
        access_key (str): Access key of the S3 compatible storage
        secret_key (str): Secret key of the S3 compatible storage

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
    sync_credentials_action = await leader_unit.run_action(
        action_name="sync-s3-credentials",
        **{
            "access-key": access_key,
            "secret-key": secret_key,
        },
    )
    return await ops_test.model.get_action_output(
        action_uuid=sync_credentials_action.entity_id, wait=120
    )


async def run_create_backup_action(ops_test: OpsTest) -> dict:
    """Run the `create-backup` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    create_backup_action = await leader_unit.run_action(
        action_name="create-backup",
    )
    return await ops_test.model.get_action_output(
        action_uuid=create_backup_action.entity_id, wait=120
    )


async def run_list_backups_action(ops_test: OpsTest) -> dict:
    """Run the `list-backups` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    list_backups_action = await leader_unit.run_action(
        action_name="list-backups",
    )
    return await ops_test.model.get_action_output(
        action_uuid=list_backups_action.entity_id, wait=120
    )


async def run_restore_backup_action(ops_test: OpsTest, backup_id: str) -> dict:
    """Run the `restore-backup` action on the `vault-k8s` leader unit.

    Args:
        ops_test (OpsTest): OpsTest
        backup_id (str): Backup ID
        root_token (str): Root token of the Vault
        unseal_keys (List[str]): Unseal keys of the Vault

    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    restore_backup_action = await leader_unit.run_action(
        action_name="restore-backup",
        **{"backup-id": backup_id},
    )
    await restore_backup_action.wait()
    return restore_backup_action.results


async def read_vault_unit_statuses(
    ops_test: OpsTest, app_name: str = APPLICATION_NAME
) -> List[Dict[str, str]]:
    """Read the complete status from vault units.

    Reads the statuses that juju emits that aren't captured by ops_test together. Captures a vault
    units: name, status (active, blocked etc.), agent (idle, executing), address and message.

    Args:
        ops_test: Ops test Framework
        app_name: Application name of the Vault, defaults to "vault-k8s"
    """
    status_tuple = await ops_test.juju("status")
    if status_tuple[0] != 0:
        raise Exception
    output = []
    for row in status_tuple[1].split("\n"):
        if not row.startswith(f"{app_name}/"):
            continue
        cells = row.split(maxsplit=4)
        if len(cells) < 5:
            cells.append("")
        output.append(
            {
                "unit": cells[0],
                "status": cells[1],
                "agent": cells[2],
                "address": cells[3],
                "message": cells[4],
            }
        )
    return output


def unseal_vault(endpoint: str, root_token: str, unseal_key: str):
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    if not client.sys.is_sealed():
        return
    client.sys.submit_unseal_key(unseal_key)


def unseal_all_vaults(unit_addresses: List[str], root_token: str, unseal_key: str):
    for endpoint in unit_addresses:
        unseal_vault(endpoint, root_token, unseal_key)


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str = APPLICATION_NAME, attempts: int = 3
) -> Any | Dict:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    secret = await ops_test.model.add_secret(f"approle-token-{app_name}", [f"token={root_token}"])
    secret_id = secret.split(":")[-1]
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)
    authorize_action = await leader_unit.run_action(
        action_name="authorize-charm",
        **{
            "secret-id": secret_id,
        },
    )
    for _ in range(attempts):
        result = await ops_test.model.get_action_output(
            action_uuid=authorize_action.entity_id, wait=120
        )
        if result and "result" in result:
            return result
        await asyncio.sleep(5)
    raise ActionFailedError("Failed to authorize charm")


def get_vault_pki_intermediate_ca_common_name(root_token: str, endpoint: str, mount: str) -> str:
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    ca_cert = client.secrets.pki.read_ca_certificate(mount_point=mount)
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )


def revoke_token(token_to_revoke: str, root_token: str, endpoint: str):
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    client.revoke_token(token=token_to_revoke)
