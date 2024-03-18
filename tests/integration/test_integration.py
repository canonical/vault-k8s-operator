#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
import os
import shutil
import time
from os.path import abspath
from pathlib import Path
from typing import List

import hvac
import pytest
import yaml
from juju.application import Application
from juju.unit import Unit
from lightkube import Client as KubernetesClient
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import crash_pod, get_leader_unit

logger = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

APPLICATION_NAME = "vault-k8s"
LOKI_APPLICATION_NAME = "loki-k8s"
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
TRAEFIK_APPLICATION_NAME = "traefik"
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
VAULT_UNIT_ADDRESS = "https://vault-k8s-0.vault-k8s-endpoints.vault.svc.cluster.local:8200"
VAULT_UNIT_DOMAIN = ".vault-k8s-endpoints.vault.svc.cluster.local"

k8s = KubernetesClient()


@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def build_charms_and_deploy_vault(ops_test: OpsTest):
    """Build the charms that are required in this test module and deploy Vault."""
    copy_lib_content()
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    built_charms = await ops_test.build_charms(".", f"{VAULT_KV_REQUIRER_CHARM_DIR}/")
    vault_charm = built_charms.get("vault-k8s", "")
    vault_kv_requirer_charm = built_charms.get("vault-kv-requirer", "")

    await ops_test.model.deploy(
        vault_charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
        series="jammy",
        num_units=NUM_VAULT_UNITS,
        config={"common_name": "example.com"},
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )

    return {"vault-kv-requirer": vault_kv_requirer_charm}


async def activate_vault(self, ops_test: OpsTest, build_charms_and_deploy_vault):
    vault_endpoints = [
        f"https://{APPLICATION_NAME}-{i}.{VAULT_UNIT_DOMAIN}:8200" for i in range(NUM_VAULT_UNITS)
    ]
    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    with open("ca_file.txt", mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    # client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
    # run vault init on first unit
    # run vault unseal on first unit
    # wait until the rest are blocked
    # run vault unseal on all units
    # authorize charm action on the leader
    pass


class TestVaultK8s:
    """This test class tests vault's deployment and activation."""

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_pod_crashes_then_unit_recovers(
        self, ops_test: OpsTest, build_charms_and_deploy_vault: dict[str, Path | str]
    ):
        assert ops_test.model
        unit = ops_test.model.units[f"{APPLICATION_NAME}/1"]
        assert isinstance(unit, Unit)
        k8s_namespace = ops_test.model.name
        crash_pod(name=f"{APPLICATION_NAME}-1", namespace=k8s_namespace)
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
        self, ops_test: OpsTest, build_charms_and_deploy_vault: dict[str, Path | str]
    ):
        assert ops_test.model
        num_units = NUM_VAULT_UNITS + 2
        app: Application = ops_test.model.applications[APPLICATION_NAME]
        await app.scale(num_units)

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=num_units,
        )

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
        self, ops_test: OpsTest, build_charms_and_deploy_vault: dict[str, Path | str]
    ):
        assert ops_test.model
        app: Application = ops_test.model.applications[APPLICATION_NAME]
        await app.scale(NUM_VAULT_UNITS)

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )


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

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self, ops_test: OpsTest, build_charms_and_deploy_vault: dict[str, Path | str]
    ):
        assert ops_test.model

        deploy_self_signed_certificates = ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
        deploy_traefik = ops_test.model.deploy(
            "traefik-k8s",
            application_name=TRAEFIK_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
        deploy_vault_kv_requirer = ops_test.model.deploy(
            build_charms_and_deploy_vault.get("vault-kv-requirer", ""),
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
            TRAEFIK_APPLICATION_NAME,
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            VAULT_KV_REQUIRER_APPLICATION_NAME,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
        ]
        await asyncio.gather(
            deploy_traefik,
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
    async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
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
    async def test_given_vault_pki_relation_when_integrate_then_cert_is_provided(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

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
        assert action_output["certificate"] is not None
        assert action_output["ca-certificate"] is not None
        assert action_output["csr"] is not None

    @pytest.mark.abort_on_fail
    async def test_given_traefik_is_deployed_when_related_to_self_signed_certificates_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{TRAEFIK_APPLICATION_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_traefik_is_deployed_when_certificate_transfer_interface_is_related_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:send-ca-cert",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:receive-ca-cert",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_certificate_transfer_interface_is_related_when_relate_to_ingress_then_status_is_active(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model
        await ops_test.model.integrate(
            relation1=f"{APPLICATION_NAME}:ingress",
            relation2=f"{TRAEFIK_APPLICATION_NAME}:ingress",
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, TRAEFIK_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    @pytest.mark.abort_on_fail
    async def test_given_given_traefik_is_related_when_vault_status_checked_then_vault_returns_200_or_429(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        """This proves that vault is reachable behind ingress."""
        vault_endpoint = await _get_vault_traefik_endpoint(ops_test)
        action_output = await run_get_ca_certificate_action(ops_test)
        ca_certificate = action_output["ca-certificate"]
        with open("ca_file.txt", mode="w+") as ca_file:
            ca_file.write(ca_certificate)
        client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
        response = client.sys.read_health_status()
        # As we have multiple Vault units, the one who gives the response could be in active or standby.  # noqa: E501, W505
        # According to the Vault upstream code, expected response codes could be "200"
        # if the unit is active or "429" if the unit is standby.
        # https://github.com/hashicorp/vault/blob/3c42b15260de8b94388ed2296fc18e89ea80c4c9/vault/logical_system_paths.go#L152  # noqa: E501, W505
        # Summary: "Returns the health status of Vault.",
        # 200: {{Description: "initialized, unsealed, and active"}}
        # 429: {{Description: "unsealed and standby"}}
        # 472: {{Description: "data recovery mode replication secondary and active"}}
        # 501: {{Description: "not initialized"}}
        # 503: {{Description: "sealed"}}
        assert response.status_code in (200, 429)
        os.remove("ca_file.txt")

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_created_then_existing_certificate_replaced(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results["stdout"]

        await ops_test.model.integrate(
            relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
            relation2=f"{APPLICATION_NAME}:tls-certificates-access",
        )

        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        final_ca_cert = action.results["stdout"]
        assert initial_ca_cert != final_ca_cert

    @pytest.mark.abort_on_fail
    async def test_given_vault_deployed_when_tls_access_relation_destroyed_then_self_signed_cert_created(
        self, ops_test: OpsTest, deploy_requiring_charms: None
    ):
        assert ops_test.model

        vault_leader_unit = ops_test.model.units[f"{APPLICATION_NAME}/0"]
        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        await action.wait()
        initial_ca_cert = action.results

        await ops_test.model.applications[APPLICATION_NAME].remove_relation(
            "tls-certificates-access", f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates"
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

        action = await vault_leader_unit.run("cat /var/lib/juju/storage/certs/0/ca.pem")
        final_ca_cert = action.results
        assert initial_ca_cert != final_ca_cert


class TestVaultK8sIntegrationsPart2:
    """Test some of the integrations and the related actions between Vault and its relations.

    The relations under test are:
        providing:
            metrics-endpoint
        requiring:
            logging,
            s3-parameters
    """

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="class")
    async def deploy_requiring_charms(
        self, ops_test: OpsTest, build_charms_and_deploy_vault: dict[str, Path | str]
    ):
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
            ops_test,
            backup_id=backup_id,
            root_token="RandomRootToken",
            unseal_keys=["RandomUnsealKey"],
        )
        assert restore_backup_action_output["restored"] == backup_id

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


async def _get_vault_traefik_endpoint(ops_test: OpsTest, timeout: int = 60) -> str:
    """Retrieve the Vault endpoint by using Traefik's `show-proxied-endpoints` action.

    Args:
        ops_test: Ops test Framework.
        timeout: Wait time in seconds to get proxied endpoints.

    Returns:
        vault_endpoint: Vault proxied endpoint by Traefik.

    Raises:
        TimeoutError: If proxied endpoints are not retrieved.

    """
    assert ops_test.model
    traefik = ops_test.model.applications[TRAEFIK_APPLICATION_NAME]
    assert isinstance(traefik, Application)
    traefik_unit = traefik.units[0]
    t0 = time.time()
    while time.time() - t0 < timeout:
        proxied_endpoint_action = await traefik_unit.run_action(
            action_name="show-proxied-endpoints"
        )
        action_output = await ops_test.model.get_action_output(
            action_uuid=proxied_endpoint_action.entity_id, wait=30
        )

        if "proxied-endpoints" in action_output:
            proxied_endpoints = json.loads(action_output["proxied-endpoints"])
            return proxied_endpoints[APPLICATION_NAME]["url"]
        else:
            logger.info("Traefik did not return proxied endpoints yet")
        time.sleep(2)

    raise TimeoutError("Traefik did not return proxied endpoints")


async def _get_vault_unit_endpoint():
    pass


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


async def run_restore_backup_action(
    ops_test: OpsTest, backup_id: str, root_token: str, unseal_keys: List[str]
) -> dict:
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
        **{
            "backup-id": backup_id,
            "unseal-keys": unseal_keys,
            "root-token": root_token,
        },
    )
    restore_backup_action_output = await ops_test.model.get_action_output(
        action_uuid=restore_backup_action.entity_id, wait=120
    )
    return restore_backup_action_output


def copy_lib_content() -> None:
    shutil.copyfile(src=VAULT_KV_LIB_DIR, dst=f"{VAULT_KV_REQUIRER_CHARM_DIR}/{VAULT_KV_LIB_DIR}")
