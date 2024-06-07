#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import hvac
import pytest
import yaml
from cryptography import x509
from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import crash_pod, get_leader_unit

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
MINIO_APPLICATION_NAME = "minio"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
MINIO_CONFIG = {
    "access-key": MINIO_S3_ACCESS_KEY,
    "secret-key": MINIO_S3_SECRET_KEY,
}

NUM_VAULT_UNITS = 3


@pytest.fixture(scope="module")
async def deploy_vault(ops_test: OpsTest, request):
    """Deploy Vault."""
    assert ops_test.model
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    charm_path = Path(request.config.getoption("--charm_path")).resolve()
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
async def initialize_leader_vault(
    ops_test: OpsTest, deploy_vault: Dict[str, Path | str]
) -> Tuple[int, str, str]:
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    leader_unit_index = int(leader_unit.name.split("/")[-1])
    unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]

    client = hvac.Client(url=f"https://{unit_addresses[leader_unit_index]}:8200", verify=False)
    initialize_response = client.sys.initialize(secret_shares=1, secret_threshold=1)
    root_token, unseal_key = initialize_response["root_token"], initialize_response["keys"][0]
    return leader_unit_index, root_token, unseal_key


class TestVaultK8s:
    """This test class tests vault's deployment and activation."""

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_and_initialized_when_unsealed_and_authorized_then_status_is_active(
        self, ops_test: OpsTest, initialize_leader_vault: Tuple[int, str, str]
    ):
        assert ops_test.model
        leader_unit_index, root_token, unseal_key = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        async with ops_test.fast_forward(fast_interval="10s"):
            unseal_vault(unit_addresses[leader_unit_index], root_token, unseal_key)
            await wait_for_vault_status_message(
                ops_test=ops_test,
                count=1,
                expected_message="Please authorize charm (see `authorize-charm` action)",
            )
            unseal_all_vaults(ops_test, unit_addresses, root_token, unseal_key)
            await wait_for_vault_status_message(
                ops_test=ops_test,
                count=NUM_VAULT_UNITS,
                expected_message="Please authorize charm (see `authorize-charm` action)",
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
        deploy_vault: dict[str, Path | str],
        initialize_leader_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = initialize_leader_vault
        crashing_pod_index = 1
        k8s_namespace = ops_test.model.name
        crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
        await wait_for_vault_status_message(
            ops_test, count=1, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[crashing_pod_index], root_token, unseal_key)
        async with ops_test.fast_forward(fast_interval="10s"):
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
        deploy_vault: dict[str, Path | str],
        initialize_leader_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, unseal_key = initialize_leader_vault
        num_units = NUM_VAULT_UNITS + 1
        app = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(app, Application)
        await app.scale(num_units)

        await wait_for_vault_status_message(
            ops_test, count=1, expected_message="Please unseal Vault", timeout=300
        )
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_vault(unit_addresses[-1], root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="10s"):
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
        deploy_vault: dict[str, Path | str],
        initialize_leader_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        _, root_token, _ = initialize_leader_vault
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
            vault-kv,
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
        deploy_vault: dict[str, Path | str],
        initialize_leader_vault: Tuple[int, str, str],
        request,
    ):
        assert ops_test.model
        kv_requirer_charm_path = Path(request.config.getoption("--kv_requirer_charm_path")).resolve()
        deploy_self_signed_certificates = ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
        deploy_vault_kv_requirer = ops_test.model.deploy(
            kv_requirer_charm_path,
            application_name=VAULT_KV_REQUIRER_APPLICATION_NAME,
            num_units=1,
        )
        deploy_vault_pki_requirer = ops_test.model.deploy(
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
            application_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            channel="stable",
            config={"common_name": "test.example.com"},
        )
        deployed_apps = [
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            VAULT_KV_REQUIRER_APPLICATION_NAME,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
        ]
        await asyncio.gather(
            deploy_self_signed_certificates,
            deploy_vault_pki_requirer,
            deploy_vault_kv_requirer,
        )
        await ops_test.model.wait_for_idle(
            apps=deployed_apps,
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )

        _, root_token, unseal_key = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(ops_test, unit_addresses, root_token, unseal_key)
        yield
        remove_coroutines = [
            ops_test.model.remove_application(app_name=app_name)
            for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
        self, ops_test, deploy_requiring_charms: None
    ):
        secret_key = "test-key"
        secret_value = "test-value"
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_APPLICATION_NAME]
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
        self, ops_test, deploy_requiring_charms: None
    ):
        secret_key = "test-key"
        secret_value = "test-value"
        vault_kv_application = ops_test.model.applications[VAULT_KV_REQUIRER_APPLICATION_NAME]
        vault_kv_unit = vault_kv_application.units[0]
        k8s_namespace = ops_test.model.name

        crash_pod(
            name=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}-0",
            namespace=k8s_namespace,
        )

        await ops_test.model.wait_for_idle(
            apps=[VAULT_KV_REQUIRER_APPLICATION_NAME],
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
        initialize_leader_vault: Tuple[int, str, str],
    ):
        assert ops_test.model
        leader_unit_index, root_token, _ = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
            mount="charm-pki",
        )
        assert current_issuers_common_name == "unmatching-the-requirer.com"
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:vault-pki",
            relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        action_output = await run_get_certificate_action(ops_test)
        assert action_output.get("certificate") is None

    @pytest.mark.abort_on_fail
    async def test_given_vault_pki_relation_and_matching_common_name_configured_when_integrate_then_cert_is_provided(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        initialize_leader_vault: Tuple[int, str, str]
    ):
        assert ops_test.model

        vault_app = ops_test.model.applications[APPLICATION_NAME]
        assert vault_app
        common_name = "example.com"
        common_name_config = {
            "common_name": common_name,
        }
        await vault_app.set_config(common_name_config)
        leader_unit_index, root_token, _ = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        current_issuers_common_name = get_vault_pki_intermediate_ca_common_name(
            root_token=root_token,
            endpoint=unit_addresses[leader_unit_index],
            mount="charm-pki",
        )
        assert current_issuers_common_name == common_name
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        action_output = await run_get_certificate_action(ops_test)
        assert action_output["certificate"] is not None
        assert action_output["ca-certificate"] is not None
        assert action_output["csr"] is not None

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_created_then_existing_certificate_replaced(
        self,
        ops_test: OpsTest,
        deploy_requiring_charms: None,
        initialize_leader_vault: Tuple[int, str, str],
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

        _, root_token, unseal_key = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(ops_test, unit_addresses, root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="10s"):
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
        initialize_leader_vault: Tuple[int, str, str],
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

        _, root_token, unseal_key = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(ops_test, unit_addresses, root_token, unseal_key)

        async with ops_test.fast_forward(fast_interval="10s"):
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
        deploy_vault: dict[str, Path | str],
        initialize_leader_vault: Tuple[int, str, str],
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
            channel="stable",
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

        _, root_token, unseal_key = initialize_leader_vault
        unit_addresses = [row["address"] for row in await read_vault_unit_statuses(ops_test)]
        unseal_all_vaults(ops_test, unit_addresses, root_token, unseal_key)
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
        minio_ip = (
            status.applications[MINIO_APPLICATION_NAME]
            .units[f"{MINIO_APPLICATION_NAME}/0"]
            .address
        )
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


async def run_get_certificate_action(ops_test) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
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


async def read_vault_unit_statuses(ops_test: OpsTest) -> List[Dict[str, str]]:
    """Read the complete status from vault units.

    Reads the statuses that juju emits that aren't captured by ops_test together. Captures a vault
    units: name, status (active, blocked etc.), agent (idle, executing), address and message.

    Args:
        ops_test: Ops test Framework
    """
    status_tuple = await ops_test.juju("status")
    if status_tuple[0] != 0:
        raise Exception
    output = []
    for row in status_tuple[1].split("\n"):
        if not row.startswith(f"{APPLICATION_NAME}/"):
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


async def wait_for_vault_status_message(
    ops_test: OpsTest, count: int, expected_message: str, timeout: int = 100, cadence: int = 2
) -> None:
    """Wait for the correct vault status messages to appear.

    This function is necessary because ops_test doesn't provide the facilities to discriminate
    depending on the status message of the units, just the statuses themselves.

    Args:
        ops_test: Ops test Framework.
        count: How many units that are expected to be emitting the expected message
        expected_message: The message that vault units should be setting as a status message
        timeout: Wait time in seconds to get proxied endpoints.
        cadence: How long to wait before running the command again

    Raises:
        TimeoutError: If the expected amount of statuses weren't found in the given timeout.
    """
    while timeout > 0:
        vault_status = await read_vault_unit_statuses(ops_test)
        seen = 0
        for row in vault_status:
            if row.get("message") == expected_message:
                seen += 1

        if seen == count:
            return
        time.sleep(cadence)
        timeout -= cadence
    raise TimeoutError("Vault didn't show the expected status")

def unseal_vault(endpoint: str, root_token: str, unseal_key: str):
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    if not client.sys.is_sealed():
        return
    client.sys.submit_unseal_key(unseal_key)


def unseal_all_vaults(
    ops_test: OpsTest, unit_addresses: List[str], root_token: str, unseal_key: str
):
    for endpoint in unit_addresses:
        unseal_vault(endpoint, root_token, unseal_key)


async def authorize_charm(ops_test: OpsTest, root_token: str) -> Any | Dict:
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
    authorize_action = await leader_unit.run_action(
        action_name="authorize-charm",
        **{
            "token": root_token,
        },
    )
    result = await ops_test.model.get_action_output(
        action_uuid=authorize_action.entity_id, wait=120
    )
    return result

def get_vault_pki_intermediate_ca_common_name(root_token: str, endpoint: str, mount: str) -> str:
    client = hvac.Client(url=f"https://{endpoint}:8200", verify=False)
    client.token = root_token
    ca_cert = client.secrets.pki.read_ca_certificate(mount_point=mount)
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )
