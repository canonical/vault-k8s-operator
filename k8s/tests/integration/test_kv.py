# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_1_APPLICATION_NAME,
    VAULT_KV_REQUIRER_2_APPLICATION_NAME,
)
from helpers import (
    crash_pod,
    deploy_vault,
    fast_forward,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(
    juju: jubilant.Juju, vault_charm_path: Path, kv_requirer_charm_path: Path, skip_deploy: bool
) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)
    deploy_vault(juju, charm_path=vault_charm_path, num_units=NUM_VAULT_UNITS)
    juju.deploy(kv_requirer_charm_path, VAULT_KV_REQUIRER_1_APPLICATION_NAME)

    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            and jubilant.all_active(s, VAULT_KV_REQUIRER_1_APPLICATION_NAME)
        ),
    )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APPLICATION_NAME}:vault-kv",
        f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}:vault-kv",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME)
                and all(
                    u.juju_status.current == "idle"
                    for app in [APPLICATION_NAME, VAULT_KV_REQUIRER_1_APPLICATION_NAME]
                    for u in s.apps[app].units.values()
                )
            ),
            timeout=SHORT_TIMEOUT,
        )


@pytest.mark.abort_on_fail
def test_given_vault_kv_requirer_related_when_create_secret_then_secret_is_created(
    juju: jubilant.Juju, deploy: VaultInit
):
    secret_key = "test-key"
    secret_value = "test-value"

    juju.run(
        f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}/0",
        "create-secret",
        {"key": secret_key, "value": secret_value},
        wait=30,
    )

    task = juju.run(
        f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}/0",
        "get-secret",
        {"key": secret_key},
        wait=30,
    )

    assert task.results["value"] == secret_value


@pytest.mark.abort_on_fail
def test_given_vault_kv_requirer_related_and_requirer_pod_crashes_when_create_secret_then_secret_is_created(
    juju: jubilant.Juju, deploy: VaultInit
):
    secret_key = "test-key"
    secret_value = "test-value"
    k8s_namespace = juju.model
    assert k8s_namespace is not None

    crash_pod(
        name=f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}-0",
        namespace=k8s_namespace,
    )

    juju.wait(
        lambda s: (
            jubilant.all_active(s, VAULT_KV_REQUIRER_1_APPLICATION_NAME)
            and len(s.apps[VAULT_KV_REQUIRER_1_APPLICATION_NAME].units) == 1
            and all(
                u.juju_status.current == "idle"
                for u in s.apps[VAULT_KV_REQUIRER_1_APPLICATION_NAME].units.values()
            )
        ),
    )

    juju.run(
        f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}/0",
        "create-secret",
        {"key": secret_key, "value": secret_value},
        wait=30,
    )

    task = juju.run(
        f"{VAULT_KV_REQUIRER_1_APPLICATION_NAME}/0",
        "get-secret",
        {"key": secret_key},
        wait=30,
    )

    assert task.results["value"] == secret_value


@pytest.mark.abort_on_fail
def test_given_multiple_kv_requirers_related_when_secrets_created_then_secrets_created(
    juju: jubilant.Juju, kv_requirer_charm_path: Path
):
    juju.deploy(kv_requirer_charm_path, VAULT_KV_REQUIRER_2_APPLICATION_NAME)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, VAULT_KV_REQUIRER_2_APPLICATION_NAME),
        )
    juju.integrate(
        f"{APPLICATION_NAME}:vault-kv",
        f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}:vault-kv",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME, VAULT_KV_REQUIRER_2_APPLICATION_NAME)
                and all(
                    u.juju_status.current == "idle"
                    for app in [APPLICATION_NAME, VAULT_KV_REQUIRER_2_APPLICATION_NAME]
                    for u in s.apps[app].units.values()
                )
            ),
            timeout=SHORT_TIMEOUT,
        )
    secret_key = "test-key-2"
    secret_value = "test-value-2"

    juju.run(
        f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}/0",
        "create-secret",
        {"key": secret_key, "value": secret_value},
        wait=30,
    )

    task = juju.run(
        f"{VAULT_KV_REQUIRER_2_APPLICATION_NAME}/0",
        "get-secret",
        {"key": secret_key},
        wait=30,
    )

    assert task.results["value"] == secret_value
