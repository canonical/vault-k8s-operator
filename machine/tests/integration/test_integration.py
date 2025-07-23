#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from asyncio import Task, create_task, gather
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest
import yaml
from cryptography import x509
from juju.application import Application
from pytest_operator.plugin import OpsTest
from vault import Vault  # type: ignore[import]

from tests.integration.helpers import (
    deploy_if_not_exists,
    deploy_vault_and_wait,
    get_app,
    get_ca_cert_file_location,
    get_juju_secret,
    get_leader,
    get_leader_unit,
    get_leader_unit_address,
    has_relation,
    refresh_application,
    run_get_certificate_action,
    unseal_all_vault_units,
    wait_for_certificate_to_be_provided,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
GRAFANA_AGENT_SERIES = "jammy"
GRAFANA_AGENT_CHANNEL = "1/stable"
PEER_RELATION_NAME = "vault-peers"
INGRESS_RELATION_NAME = "ingress"
HAPROXY_APPLICATION_NAME = "haproxy"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_REVISION = 263
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
NUM_VAULT_UNITS = 3
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MATCHING_COMMON_NAME = "example.com"
UNMATCHING_COMMON_NAME = "unmatching-the-requirer.com"
VAULT_PKI_REQUIRER_REVISION = 93
CURRENT_TRACK_FIRST_STABLE_REVISION = 387
CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.16/stable"


class ActionFailedError(Exception):
    """Exception raised when an action fails."""

    pass


@pytest.fixture(scope="session")
def vault_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--charm_path"))).resolve()


@pytest.fixture(scope="session")
def kv_requirer_charm_path(request: pytest.FixtureRequest) -> Path:
    return Path(str(request.config.getoption("--kv_requirer_charm_path"))).resolve()


@pytest.fixture(scope="function")
async def vault_idle(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be blocked.

    This is the default state of Vault.
    """
    return create_task(
        deploy_vault_and_wait(
            ops_test=ops_test, num_units=NUM_VAULT_UNITS, charm_path=vault_charm_path
        )
    )


@pytest.fixture(scope="function")
async def vault_idle_blocked(
    ops_test: OpsTest, request: pytest.FixtureRequest, vault_charm_path: Path
) -> Task:
    """Deploy the Vault charm, and wait for it to be blocked.

    This is the default state of Vault.
    """
    return create_task(
        deploy_vault_and_wait(
            ops_test=ops_test,
            num_units=NUM_VAULT_UNITS,
            charm_path=vault_charm_path,
            status="blocked",
        )
    )


@pytest.fixture(scope="function")
async def vault_initialized(ops_test: OpsTest, vault_idle: Task) -> Task:
    async def deploy_and_initialize():
        assert ops_test.model

        await vault_idle
        return await initialize_vault_leader(ops_test, APP_NAME)

    return create_task(deploy_and_initialize())


@pytest.fixture(scope="function")
async def vault_unsealed(ops_test: OpsTest, vault_initialized: Task) -> Task:
    assert ops_test.model
    root_token, unseal_key = await vault_initialized

    async def task():
        await unseal_all_vault_units(
            ops_test, await get_ca_cert_file_location(ops_test), unseal_key
        )
        return root_token, unseal_key

    return create_task(task())


@pytest.fixture(scope="function")
async def vault_authorized(ops_test: OpsTest, vault_unsealed: Task) -> Task:
    assert ops_test.model
    root_token, key = await vault_unsealed

    async def authorize():
        try:
            await authorize_charm(ops_test, root_token)
        except ActionFailedError:
            logger.warning("Failed to authorize charm")
        return root_token, key

    return create_task(authorize())


@pytest.fixture(scope="module")
async def self_signed_certificates_idle(ops_test: OpsTest) -> Task:
    """Deploy the `self-signed-certificates` charm."""

    async def deploy_self_signed_certificates(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model,
            SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
            channel="1/stable",
            revision=SELF_SIGNED_CERTIFICATES_REVISION,
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            )

    return create_task(deploy_self_signed_certificates(ops_test))


@pytest.fixture(scope="module")
async def haproxy_idle(ops_test: OpsTest) -> Task:
    """Deploy the `haproxy` charm."""

    async def deploy_haproxy(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(ops_test.model, HAPROXY_APPLICATION_NAME, channel="2.8/edge")
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[HAPROXY_APPLICATION_NAME],
            )

    return create_task(deploy_haproxy(ops_test))


@pytest.fixture(scope="module")
async def vault_kv_requirer_idle(ops_test: OpsTest, kv_requirer_charm_path: Path) -> Task:
    """Deploy the `vault-kv-requirer` charm."""

    async def deploy_kv_requirer(ops_test: OpsTest) -> None:
        assert ops_test.model
        await deploy_if_not_exists(
            ops_test.model, VAULT_KV_REQUIRER_APPLICATION_NAME, charm_path=kv_requirer_charm_path
        )
        async with ops_test.fast_forward(fast_interval="60s"):
            await ops_test.model.wait_for_idle(
                apps=[VAULT_KV_REQUIRER_APPLICATION_NAME],
            )

    return create_task(deploy_kv_requirer(ops_test))


@pytest.fixture(scope="module")
async def vault_pki_requirer_idle(ops_test: OpsTest) -> Task:
    """Deploy the `vault-pki-requirer` charm."""

    async def deploy_pki_requirer(ops_test: OpsTest):
        assert ops_test.model
        config = {
            "common_name": f"test.{MATCHING_COMMON_NAME}",
            "sans_dns": f"test.{MATCHING_COMMON_NAME}",
        }
        await deploy_if_not_exists(
            ops_test.model,
            VAULT_PKI_REQUIRER_APPLICATION_NAME,
            config=config,
            revision=VAULT_PKI_REQUIRER_REVISION,
            channel="stable",
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
        )

    return create_task(deploy_pki_requirer(ops_test))


@pytest.fixture(scope="module")
async def grafana_deployed(ops_test: OpsTest) -> Task:
    """Deploy the `grafana-agent` charm."""
    assert ops_test.model

    return create_task(
        deploy_if_not_exists(
            ops_test.model,
            GRAFANA_AGENT_APPLICATION_NAME,
            channel=GRAFANA_AGENT_CHANNEL,
            series=GRAFANA_AGENT_SERIES,
        )
    )


@pytest.fixture(scope="module")
async def s3_integrator_idle(ops_test: OpsTest) -> Task:
    """Deploy the `s3-integrator` charm."""

    async def deploy_s3_integrator(ops_test: OpsTest):
        assert ops_test.model

        await deploy_if_not_exists(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
        )

    return create_task(deploy_s3_integrator(ops_test))


def get_vault_pki_intermediate_ca_common_name(
    root_token: str, unit_address: str, mount: str
) -> str:
    vault = Vault(
        url=f"https://{unit_address}:8200",
        token=root_token,
    )
    ca_cert = vault.client.secrets.pki.read_ca_certificate(mount_point=mount)
    assert ca_cert, "No CA certificate found"
    loaded_certificate = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )


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


async def get_leader_vault_client(ops_test: OpsTest, app_name: str) -> Vault:
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    vault_url = f"https://{leader_ip}:8200"
    ca_file_location = get_ca_cert_file_location(ops_test)
    return Vault(url=vault_url, ca_file_location=await ca_file_location)


async def initialize_vault_leader(ops_test: OpsTest, app_name: str) -> Tuple[str, str]:
    """Initialize the leader vault unit and return the root token and unseal key.

    Returns:
        Tuple[str, str]: Root token and unseal key
    """
    assert ops_test.model
    app = ops_test.model.applications[app_name]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader
    leader_ip = leader.public_address
    vault_url = f"https://{leader_ip}:8200"

    vault = Vault(
        url=vault_url, ca_file_location=await get_ca_cert_file_location(ops_test, app_name)
    )
    if not vault.is_initialized():
        root_token, key = vault.initialize()
        await ops_test.model.add_secret(
            f"root-token-key-{app_name}", [f"root-token={root_token}", f"key={key}"]
        )
        return root_token, key

    root_token, key = await get_juju_secret(
        ops_test.model, label=f"root-token-key-{app_name}", fields=["root-token", "key"]
    )
    return root_token, key


async def authorize_charm(
    ops_test: OpsTest, root_token: str, app_name: str = APP_NAME
) -> Any | Dict:
    """Authorize the charm to interact with Vault.

    Returns:
        Action output
    """
    assert ops_test.model

    assert isinstance(app := ops_test.model.applications[app_name], Application)
    if app.status == "active":
        logger.info("The charm is already active, skipping authorization.")
        return
    logger.info("Authorizing the charm `%s` to interact with Vault.", app_name)
    secret = await ops_test.model.add_secret(f"approle-token-{app_name}", [f"token={root_token}"])
    secret_id = secret.split(":")[-1]
    await ops_test.model.grant_secret(f"approle-token-{app_name}", app_name)
    leader_unit = await get_leader_unit(ops_test.model, app_name)
    authorize_action = await leader_unit.run_action(
        action_name="authorize-charm",
        **{
            "secret-id": secret_id,
        },
    )
    result = await ops_test.model.get_action_output(
        action_uuid=authorize_action.entity_id, wait=120
    )
    if not result or "result" not in result:
        raise ActionFailedError("Failed to authorize charm")
    logger.info("Authorization result: %s", result)
    return result


async def test_deploy_all_the_things(
    ops_test: OpsTest,
    vault_idle: Task,
    self_signed_certificates_idle: Task,
    haproxy_idle: Task,
    vault_kv_requirer_idle: Task,
    vault_pki_requirer_idle: Task,
    grafana_deployed: Task,
    s3_integrator_idle: Task,
):
    """Deplay all the charms, but don't wait for them to be idle.

    This is not a real test, but a way to deploy all the charms in one go right
    at the start of the test run. This is useful when running all the tests at
    once. If tests are individually selected, the charms will be deployed as
    needed by the test fixtures.
    """
    assert ops_test.model


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_then_status_blocked(
    ops_test: OpsTest, vault_idle_blocked: Task
):
    assert ops_test.model
    await vault_idle_blocked

    vault_app = get_app(ops_test.model)
    assert vault_app.status == "blocked"


@pytest.mark.abort_on_fail
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(  # noqa: E501
    ops_test: OpsTest, vault_idle_blocked: Task, self_signed_certificates_idle: Task
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    await gather(vault_idle_blocked, self_signed_certificates_idle)

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:tls-certificates-access",
    )
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(apps=[APP_NAME])
        await ops_test.model.wait_for_idle(apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME])
    vault_ip = await get_leader_unit_address(ops_test)
    vault_url = f"https://{vault_ip}:8200"
    ca_file_location = await get_ca_cert_file_location(ops_test)
    vault = Vault(url=vault_url, ca_file_location=ca_file_location)
    assert not vault.is_initialized()


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest,
    vault_initialized: Task,
    self_signed_certificates_idle: Task,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    await self_signed_certificates_idle
    root_token, unseal_key = await vault_initialized
    leader_unit_address = await get_leader_unit_address(ops_test)
    ca_file_location = await get_ca_cert_file_location(ops_test)
    vault = Vault(
        url=f"https://{leader_unit_address}:8200",
        ca_file_location=ca_file_location,
        token=root_token,
    )
    assert vault.is_sealed()
    vault.unseal(unseal_key)
    vault.wait_for_node_to_be_unsealed()
    assert vault.is_active()
    async with ops_test.fast_forward(fast_interval="60s"):
        await unseal_all_vault_units(ops_test, ca_file_location, unseal_key)
        try:
            await authorize_charm(ops_test, root_token)
        except ActionFailedError as e:
            logger.warning("Failed to authorize charm: %s", e)
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


async def test_given_haproxy_deployed_when_integrated_then_status_is_active(
    ops_test: OpsTest, haproxy_idle: Task
):
    assert ops_test.model
    await haproxy_idle

    haproxy_app = get_app(ops_test.model, HAPROXY_APPLICATION_NAME)
    external_hostname = "haproxy"
    await haproxy_app.set_config({"external-hostname": external_hostname})

    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{HAPROXY_APPLICATION_NAME}:certificates",
    )

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:ingress",
        relation2=f"{HAPROXY_APPLICATION_NAME}:ingress",
    )

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, HAPROXY_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )


@pytest.mark.abort_on_fail
@pytest.mark.dependency
async def test_given_application_is_deployed_when_scale_up_then_status_is_active(
    ops_test: OpsTest,
    vault_unsealed: Task,
):
    assert ops_test.model

    root_token, unseal_key = await vault_unsealed
    num_units = NUM_VAULT_UNITS + 1
    app = get_app(ops_test.model)
    await app.add_unit(count=1)

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=1000,
            wait_for_exact_units=num_units,
        )

    new_unit = app.units[-1]
    new_unit_address = new_unit.public_address
    vault = Vault(
        url=f"https://{new_unit_address}:8200",
        ca_file_location=await get_ca_cert_file_location(ops_test),
        token=root_token,
    )
    vault.unseal(unseal_key=unseal_key)
    vault.wait_for_node_to_be_unsealed()
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=1000,
            status="active",
        )

    vault.wait_for_raft_nodes(expected_num_nodes=num_units)


@pytest.mark.abort_on_fail
@pytest.mark.dependency(
    depends=["test_given_application_is_deployed_when_scale_up_then_status_is_active"]
)
async def test_given_application_is_deployed_when_scale_down_then_status_is_active(
    ops_test: OpsTest,
    vault_authorized: Task,
):
    await vault_authorized
    assert ops_test.model

    new_unit = get_app(ops_test.model).units[-1]
    await new_unit.remove()
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=1000,
            status="active",
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
    # Note: We are not verifying the number of nodes in the raft cluster
    # because the Vault API address is often not available during the
    # unit removal.


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, grafana_deployed: Task
):
    assert ops_test.model
    await vault_authorized
    await grafana_deployed

    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:cos-agent",
        relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            timeout=1000,
            status="active",
        )


@pytest.mark.dependency
@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, vault_kv_requirer_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await vault_kv_requirer_idle

    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "vault-kv"):
        await ops_test.model.integrate(
            relation1=f"{APP_NAME}:vault-kv",
            relation2=f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
        )
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )


@pytest.mark.dependency(
    depends=[
        "test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active"
    ]
)
@pytest.mark.abort_on_fail
async def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
    ops_test: OpsTest, vault_authorized: Task, vault_kv_requirer_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await vault_kv_requirer_idle

    secret_key = "test-key"
    secret_value = "test-value"
    vault_kv_unit = await get_leader_unit(ops_test.model, VAULT_KV_REQUIRER_APPLICATION_NAME)
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
@pytest.mark.dependency()
async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task, self_signed_certificates_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await self_signed_certificates_idle

    vault_app = get_app(ops_test.model)
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
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.wait_for_idle(
        apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
        status="active",
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
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        wait_for_exact_units=NUM_VAULT_UNITS,
    )
    await ops_test.model.wait_for_idle(
        apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
        status="active",
    )

    leader_unit_address = await get_leader_unit_address(ops_test)
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

    vault_app = get_app(ops_test.model)
    common_name = MATCHING_COMMON_NAME
    common_name_config = {
        "common_name": common_name,
    }
    await vault_app.set_config(common_name_config)
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        await ops_test.model.wait_for_idle(
            apps=[VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await wait_for_status_message(
            ops_test,
            expected_message="Unit certificate is available",
            app_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
            count=1,
            timeout=300,
        )

    leader_unit_address = await get_leader_unit_address(ops_test)
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


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    assert ops_test.model
    await vault_authorized
    await s3_integrator_idle

    s3_integrator = get_app(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
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
    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
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
    create_backup_action_output = await run_create_backup_action(ops_test)
    assert create_backup_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    await vault_authorized
    await s3_integrator_idle
    assert ops_test.model

    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
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
    list_backups_action_output = await run_list_backups_action(ops_test)
    assert list_backups_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
async def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    ops_test: OpsTest,
    vault_authorized: Task,
    s3_integrator_idle: Task,
    self_signed_certificates_idle: Task,
):
    assert ops_test.model
    await vault_authorized
    await s3_integrator_idle
    await self_signed_certificates_idle

    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    backup_id = "dummy-backup-id"

    backup_action_output = await run_restore_backup_action(ops_test, backup_id)
    assert backup_action_output.get("return-code") == 0


@pytest.mark.abort_on_fail
@pytest.mark.dependency()
async def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    ops_test: OpsTest,
    vault_authorized: Task,
    self_signed_certificates_idle: Task,
    request: pytest.FixtureRequest,
    vault_charm_path: Path,
):
    assert ops_test.model
    await vault_authorized
    await self_signed_certificates_idle

    await ops_test.model.deploy(
        vault_charm_path,
        application_name="vault-b",
        trust=True,
        num_units=1,
    )
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="blocked",
            timeout=1000,
            wait_for_exact_units=1,
        )

    await ops_test.model.integrate(
        relation1="vault-b:tls-certificates-access",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )

    ###

    await ops_test.model.integrate(
        f"{APP_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
    )
    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(
            apps=["vault-b"], status="blocked", wait_for_exact_units=1, idle_period=5
        )

        await wait_for_status_message(
            ops_test=ops_test,
            count=1,
            expected_message="Please initialize Vault",
            app_name="vault-b",
        )

        root_token, recovery_key = await initialize_vault_leader(ops_test, "vault-b")
        await wait_for_status_message(
            ops_test=ops_test,
            count=1,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            app_name="vault-b",
        )
        try:
            await authorize_charm(ops_test, root_token, "vault-b")
        except ActionFailedError:
            logger.warning("Failed to authorize charm")
        await ops_test.model.wait_for_idle(
            apps=["vault-b"],
            status="active",
            wait_for_exact_units=1,
            idle_period=5,
        )


@pytest.mark.abort_on_fail
@pytest.mark.dependency(
    depends=["test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated"]
)
async def test_given_vault_b_is_deployed_and_autounsealed_when_add_unit_then_status_is_active(
    ops_test: OpsTest, vault_authorized: Task
):
    assert ops_test.model
    await vault_authorized

    app = ops_test.model.applications["vault-b"]
    assert isinstance(app, Application)
    assert len(app.units) == 1
    await app.add_units(1)
    await ops_test.model.wait_for_idle(
        apps=["vault-b"],
        status="active",
        wait_for_exact_units=2,
        idle_period=5,
    )


async def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest,
    vault_charm_path: Path,
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    application_name_in_model = "first"
    await deploy_vault_and_wait(
        ops_test,
        app_name_in_model=application_name_in_model,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, application_name_in_model)
    async with ops_test.fast_forward(fast_interval="60s"):
        await unseal_all_vault_units(
            ops_test,
            await get_ca_cert_file_location(ops_test),
            unseal_key,
            app_name=application_name_in_model,
        )
        await authorize_charm(ops_test, root_token, app_name=application_name_in_model)
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, application_name_in_model, vault_charm_path)

        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )


async def test_given_latest_stable_revision_in_track_when_refresh_then_status_is_active(
    ops_test: OpsTest,
    vault_charm_path: Path,
):
    assert ops_test.model
    logger.info("Deploying vault from Charmhub")
    application_name_in_model = "latest"
    await deploy_vault_and_wait(
        ops_test,
        app_name_in_model=application_name_in_model,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
    )
    root_token, unseal_key = await initialize_vault_leader(ops_test, application_name_in_model)
    async with ops_test.fast_forward(fast_interval="60s"):
        await unseal_all_vault_units(
            ops_test,
            await get_ca_cert_file_location(ops_test),
            unseal_key,
            app_name=application_name_in_model,
        )
        await authorize_charm(ops_test, root_token, app_name=application_name_in_model)
        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )

        logger.info("Refreshing vault from built charm")
        await refresh_application(ops_test, application_name_in_model, vault_charm_path)

        await ops_test.model.wait_for_idle(
            apps=[application_name_in_model],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
