# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    AUTOUNSEAL_TOKEN_SECRET_LABEL,
    JUJU_FAST_INTERVAL,
    METADATA,
    NUM_VAULT_UNITS,
)
from helpers import (
    authorize_charm,
    crash_pod,
    deploy_vault,
    fast_forward,
    get_leader_unit_name,
    get_model_secret_field,
    get_unit_address,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    initialize_vault_leader,
    revoke_token,
    scale,
    wait_for_status_message,
)
from vault_helpers import Vault

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)
    resources = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
    juju.deploy(
        vault_charm_path,
        "vault-b",
        num_units=1,
        resources=resources,
        trust=True,
    )
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )

    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            and jubilant.all_blocked(s, "vault-b")
            and len(s.apps["vault-b"].units) == 1
        ),
    )

    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APPLICATION_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires"
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_blocked(s, "vault-b") and len(s.apps["vault-b"].units) == 1,
        )

        wait_for_status_message(
            juju=juju,
            expected_message="Please initialize Vault",
            app_name="vault-b",
        )

        root_token_vault_b, _ = initialize_vault_leader(juju, "vault-b")
        wait_for_status_message(
            juju=juju,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            app_name="vault-b",
        )
        authorize_charm(juju, root_token_vault_b, "vault-b")
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 1,
        )


@pytest.mark.abort_on_fail
def test_given_vault_b_is_deployed_and_unsealed_when_scale_up_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        scale(juju, "vault-b", 1)
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 1,
        )
        scale(juju, "vault-b", 3)
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 3,
        )


@pytest.mark.abort_on_fail
def test_given_vault_b_is_deployed_and_unsealed_when_all_units_crash_then_units_recover(
    juju: jubilant.Juju, deploy: VaultInit
):
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 3,
        )

    k8s_namespace = juju.model
    assert k8s_namespace is not None
    crash_pod(name="vault-b-0", namespace=k8s_namespace)
    crash_pod(name="vault-b-1", namespace=k8s_namespace)
    crash_pod(name="vault-b-2", namespace=k8s_namespace)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 3,
        )
        leader_unit_name = get_leader_unit_name(juju, "vault-b")
    leader_unit_address = get_unit_address(juju, leader_unit_name)
    root_token_vault_b, _ = get_vault_token_and_unseal_key(juju, "vault-b")
    vault = Vault(
        url=f"https://{leader_unit_address}:8200",
        token=root_token_vault_b,
    )
    vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
def test_given_vault_b_is_deployed_and_unsealed_when_auth_token_goes_bad_then_units_recover(
    juju: jubilant.Juju, deploy: VaultInit
):
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 3,
        )
    auth_token = get_model_secret_field(
        juju=juju, label=AUTOUNSEAL_TOKEN_SECRET_LABEL, field="token"
    )
    leader_unit_name = get_leader_unit_name(juju, "vault-b")
    leader_unit_address = get_unit_address(juju, leader_unit_name)
    root_token_vault_b, _ = get_vault_token_and_unseal_key(juju, "vault-b")

    revoke_token(
        token_to_revoke=auth_token,
        root_token=root_token_vault_b,
        endpoint=leader_unit_address,
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 3,
        )
