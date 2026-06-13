# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    DEPLOY_TIMEOUT,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from helpers import (
    _get_arch,
    authorize_charm_and_wait,
    crash_pod,
    deploy_vault,
    fast_forward,
    get_leader_unit_name,
    get_unit_status_messages,
    get_vault_ca_certificate,
    get_vault_client,
    get_vault_token_and_unseal_key,
    initialize_vault_leader,
    scale,
    unseal_all_vault_units,
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

    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) >= NUM_VAULT_UNITS
        ),
        timeout=DEPLOY_TIMEOUT,
    )

    root_token, unseal_key = initialize_vault_leader(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_vault_deployed_and_initialized_when_unsealed_and_authorized_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    vault = get_vault_client(juju, leader_name, deploy.root_token)
    assert vault.is_sealed()
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, deploy.unseal_key, deploy.root_token)
        authorize_charm_and_wait(juju, deploy.root_token)
    vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_pod_crashes_then_unit_recovers(
    juju: jubilant.Juju, deploy: VaultInit
):
    k8s_namespace = juju.model
    assert k8s_namespace is not None
    crashing_pod_index = 1
    crashed_unit_name = f"{APPLICATION_NAME}/{crashing_pod_index}"
    crashed_pod_name = f"{APPLICATION_NAME}-{crashing_pod_index}"

    crash_pod(name=crashed_pod_name, namespace=k8s_namespace)
    wait_for_status_message(
        juju,
        expected_message="Please unseal Vault",
        timeout=300,
        unit_name=crashed_unit_name,
    )
    vault = get_vault_client(juju, crashed_unit_name, deploy.root_token)
    vault.unseal(deploy.unseal_key)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1200,
        )


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_scale_up_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    num_units = NUM_VAULT_UNITS + 1
    scale(juju, APPLICATION_NAME, num_units)

    wait_for_status_message(juju, expected_message="Please unseal Vault", timeout=300, count=1)
    sealed = [
        unit_name
        for unit_name, status in get_unit_status_messages(juju)
        if status == "Please unseal Vault"
    ]
    assert len(sealed) == 1
    vault = get_vault_client(juju, sealed[0], deploy.root_token)
    vault.unseal(deploy.unseal_key)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == num_units
            ),
            timeout=DEPLOY_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_scale_down_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    last_unit_name = list(juju.status().apps[APPLICATION_NAME].units.keys())[-1]
    vault = get_vault_client(juju, last_unit_name, deploy.root_token)

    assert vault.number_of_raft_nodes() == NUM_VAULT_UNITS + 1

    scale(juju, APPLICATION_NAME, NUM_VAULT_UNITS)
    juju.wait(
        lambda s: (
            jubilant.all_active(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=SHORT_TIMEOUT,
    )

    first_unit_name = list(juju.status().apps[APPLICATION_NAME].units.keys())[0]
    vault = get_vault_client(juju, first_unit_name, deploy.root_token)
    assert vault.number_of_raft_nodes() == NUM_VAULT_UNITS


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_apply_k8s_resource_patch_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.config(
        APPLICATION_NAME,
        {
            "cpu-request": "0.75",
            "memory-request": "1Gi",
            "cpu-limit": "2",
            "memory-limit": "2Gi",
        },
    )
    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=DEPLOY_TIMEOUT,
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, deploy.unseal_key, deploy.root_token)
        authorize_charm_and_wait(juju, deploy.root_token)

    juju.wait(
        lambda s: (
            jubilant.all_active(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=DEPLOY_TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_self_signed_certificates_integrated_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        constraints={"arch": _get_arch()},
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME),
            timeout=DEPLOY_TIMEOUT,
        )
    juju.integrate(
        f"{APPLICATION_NAME}:tls-certificates-access",
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(
                s, APPLICATION_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME
            ),
            timeout=DEPLOY_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_tls_certificates_integrated_when_vault_ca_certificate_is_returned_then_ca_cert_is_valid(
    juju: jubilant.Juju, deploy: VaultInit
):
    leader_name = get_leader_unit_name(juju, APPLICATION_NAME)
    ca_cert = get_vault_ca_certificate(juju, leader_name)
    assert ca_cert


@pytest.mark.abort_on_fail
def test_given_tls_certificates_integrated_when_vault_unit_crashes_then_vault_uses_tls(
    juju: jubilant.Juju, deploy: VaultInit
):
    k8s_namespace = juju.model
    assert k8s_namespace is not None
    crashing_pod_index = 1
    crashed_unit_name = f"{APPLICATION_NAME}/{crashing_pod_index}"
    crashed_pod_name = f"{APPLICATION_NAME}-{crashing_pod_index}"

    crash_pod(name=crashed_pod_name, namespace=k8s_namespace)
    wait_for_status_message(
        juju,
        expected_message="Please unseal Vault",
        timeout=300,
        unit_name=crashed_unit_name,
    )

    # After the crash + TLS cert re-delivery, multiple units may need
    # unsealing (TLS reconfiguration can restart Vault on all units).
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, deploy.unseal_key, deploy.root_token)
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1200,
        )
