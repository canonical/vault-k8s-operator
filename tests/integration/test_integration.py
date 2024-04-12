#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time
from os.path import abspath
from pathlib import Path
from typing import List

import hvac
import pytest
import yaml
from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import get_leader_unit

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
PEER_RELATION_NAME = "vault-peers"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
NUM_VAULT_UNITS = 3
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_UNSEALED_AND_STANDBY = 429
VAULT_STATUS_NOT_INITIALIZED = 501
VAULT_STATUS_SEALED = 503


async def run_get_ca_certificate_action(ops_test: OpsTest, timeout: int = 60) -> dict:
    """Run the `get-certificate` on the `self-signed-certificates` unit.

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


async def validate_vault_status(
    expected_vault_status_code: int | List[int], ops_test: OpsTest, vault_client: hvac.Client
):
    assert ops_test.model
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    response = vault_client.sys.read_health_status()
    if isinstance(expected_vault_status_code, list):
        assert response.status_code in expected_vault_status_code
    else:
        assert response.status_code == expected_vault_status_code


async def get_leader(app: Application) -> Unit | None:
    for unit in app.units:
        assert isinstance(unit, Unit)
        if await unit.is_leader_from_status():
            return unit
    return None

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
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=30)
    return action_output

async def wait_for_certificate_to_be_provided(ops_test: OpsTest) -> None:
    start_time = time.time()
    timeout = 300
    while time.time() - start_time < timeout:
        action_output = await run_get_certificate_action(ops_test)
        if action_output.get("certificate", None) is not None:
            return
        time.sleep(10)
    raise TimeoutError("Timed out waiting for certificate to be provided.")

@pytest.fixture(scope="module")
async def deploy_vault(ops_test: OpsTest, request) -> None:
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm_path = Path(request.config.getoption("--charm_path")).resolve()
    await ops_test.model.deploy(
        charm_path,
        application_name=APP_NAME,
        num_units=NUM_VAULT_UNITS,
        config={"common_name": "example.com"},
    )


@pytest.fixture(scope="module")
async def deploy_requiring_charms(ops_test: OpsTest, deploy_vault: None, request):
    assert ops_test.model
    kv_requirer_charm_path = Path(request.config.getoption("--kv_requirer_charm_path")).resolve()
    deploy_self_signed_certificates = ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        num_units=1,
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
        num_units=1,
        config={"common_name": "test.example.com"},
    )
    deploy_grafana_agent = ops_test.model.deploy(
        GRAFANA_AGENT_APPLICATION_NAME,
        application_name=GRAFANA_AGENT_APPLICATION_NAME,
        num_units=1,
        channel="stable",
    )
    deploy_s3_integrator = ops_test.model.deploy(
            "s3-integrator",
            application_name=S3_INTEGRATOR_APPLICATION_NAME,
            trust=True,
            channel="stable",
        )
    deployed_apps = [
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        VAULT_KV_REQUIRER_APPLICATION_NAME,
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        GRAFANA_AGENT_APPLICATION_NAME,
        S3_INTEGRATOR_APPLICATION_NAME,
    ]
    await asyncio.gather(
        deploy_self_signed_certificates,
        deploy_vault_kv_requirer,
        deploy_vault_pki_requirer,
        deploy_grafana_agent,
        deploy_s3_integrator,
    )
    await ops_test.model.wait_for_idle(
        apps=[
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            VAULT_PKI_REQUIRER_APPLICATION_NAME
            ],
        status="active",
        timeout=1000,
        wait_for_exact_units=1,
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



async def unseal_all_vault_units(ops_test: OpsTest, ca_file_name: str, keys: str) -> None:
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)
    clients = []
    for unit in app.units:
        assert isinstance(unit, Unit)
        unit_endpoint = f"https://{unit.public_address}:8200"
        client = hvac.Client(url=unit_endpoint, verify=abspath(ca_file_name))
        if client.sys.read_health_status() not in (
            VAULT_STATUS_ACTIVE,
            VAULT_STATUS_UNSEALED_AND_STANDBY,
        ):
            client.sys.submit_unseal_keys(keys)
        clients.append(client)

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    for client in clients:
        response = client.sys.read_health_status()
        assert response.status_code in (VAULT_STATUS_ACTIVE, VAULT_STATUS_UNSEALED_AND_STANDBY)

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
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
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
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
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
        backup_id (str): Backup ID to restore
    Returns:
        dict: Action output
    """
    assert ops_test.model
    leader_unit = await get_leader_unit(ops_test.model, APP_NAME)
    restore_backup_action = await leader_unit.run_action(
        action_name="restore-backup",
        **{"backup-id": backup_id},
    )
    return await ops_test.model.get_action_output(
        action_uuid=restore_backup_action.entity_id, wait=120
    )


@pytest.mark.abort_on_fail
async def test_given_charm_build_when_deploy_then_status_blocked(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    async with ops_test.fast_forward():
        # Charm should go to blocked state because it needs to be manually
        # initialized.
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )


@pytest.mark.abort_on_fail
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:tls-certificates-access",
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    assert isinstance(unit := ops_test.model.units.get(f"{APP_NAME}/0"), Unit)
    unit_ip = unit.public_address
    vault_endpoint = f"https://{unit_ip}:8200"
    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    ca_file_location = str(ops_test.tmp_path / "ca_file.txt")
    with open(ca_file_location, mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    client = hvac.Client(url=vault_endpoint, verify=ca_file_location)
    response = client.sys.read_health_status()
    assert response.status_code == VAULT_STATUS_NOT_INITIALIZED


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader

    leader_ip = leader.public_address
    vault_endpoint = f"https://{leader_ip}:8200"

    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    ca_file_location = str(ops_test.tmp_path / "ca_file.txt")
    with open(ca_file_location, mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    client = hvac.Client(url=vault_endpoint, verify=ca_file_location)
    await validate_vault_status(VAULT_STATUS_NOT_INITIALIZED, ops_test, client)

    init_output = client.sys.initialize(secret_shares=1, secret_threshold=1)
    keys = init_output["keys"]
    root_token = init_output["root_token"]
    await validate_vault_status(VAULT_STATUS_SEALED, ops_test, client)
    client.sys.submit_unseal_keys(keys)
    await validate_vault_status(VAULT_STATUS_ACTIVE, ops_test, client)

    await unseal_all_vault_units(ops_test, ca_file.name, keys)
    await leader.run_action("authorize-charm", token=root_token)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )

@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:cos-agent",
        relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )

@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:vault-kv",
        relation2=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )

@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
    ops_test, deploy_requiring_charms: None
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
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:tls-certificates-pki",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )

@pytest.mark.abort_on_fail
async def test_given_vault_pki_relation_when_integrate_then_cert_is_provided(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:vault-pki",
        relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates"
        )
    await ops_test.model.wait_for_idle(
            apps=[APP_NAME, VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    await wait_for_certificate_to_be_provided(ops_test)
    action_output = await run_get_certificate_action(ops_test)
    assert action_output.get("certificate", None) is not None
    assert action_output.get("ca-certificate", None) is not None
    assert action_output.get("csr", None) is not None

@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_create_backup_then_action_fails(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
    assert s3_integrator
    await run_s3_integrator_sync_credentials_action(
        ops_test,
        secret_key="Dummy secret key",
        access_key="Dummy access key",
    )
    s3_config = {
        "endpoint": "http://minio-dummy:9000",
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
        relation1=APP_NAME,
        relation2=S3_INTEGRATOR_APPLICATION_NAME,
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    vault = ops_test.model.applications[APP_NAME]
    assert isinstance(vault, Application)
    create_backup_action_output = await run_create_backup_action(ops_test)
    assert create_backup_action_output.get("return-code") == 0

@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_fails(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[S3_INTEGRATOR_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    vault = ops_test.model.applications[APP_NAME]
    assert isinstance(vault, Application)
    list_backups_action_output = await run_list_backups_action(ops_test)
    assert list_backups_action_output.get("return-code") == 0

@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_restore_backup_then_action_fails(
    ops_test: OpsTest, deploy_requiring_charms: None
):
    assert ops_test.model
    vault = ops_test.model.applications[APP_NAME]
    assert isinstance(vault, Application)
    backup_id = "dummy-backup-id"

    backup_action_output = await run_restore_backup_action(ops_test, backup_id)
    assert backup_action_output.get("return-code") == 0
