import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_CHANNEL,
    SELF_SIGNED_CERTIFICATES_REVISION,
    SHORT_TIMEOUT,
    VAULT_KV_REQUIRER_APPLICATION_NAME,
)
from helpers import (
    deploy_vault,
    fast_forward,
    get_vault_token_and_unseal_key,
    has_relation,
    initialize_unseal_authorize_vault,
    run_action_on_leader,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(
    juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool, kv_requirer_charm_path: Path
) -> VaultInit:
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        root_token, key = get_vault_token_and_unseal_key(juju, APP_NAME)
        return VaultInit(root_token, key)
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel=SELF_SIGNED_CERTIFICATES_CHANNEL,
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )
    juju.deploy(kv_requirer_charm_path, VAULT_KV_REQUIRER_APPLICATION_NAME)

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and jubilant.all_active(s, VAULT_KV_REQUIRER_APPLICATION_NAME)
                and jubilant.all_blocked(s, APP_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1000,
        )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_vault_kv_requirer_deployed_when_vault_kv_relation_created_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    if not has_relation(juju, APP_NAME, "vault-kv"):
        juju.integrate(
            f"{APP_NAME}:vault-kv",
            f"{VAULT_KV_REQUIRER_APPLICATION_NAME}:vault-kv",
        )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME)
                and all(
                    u.juju_status.current == "idle"
                    for app in [APP_NAME, VAULT_KV_REQUIRER_APPLICATION_NAME]
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
    run_action_on_leader(
        juju,
        VAULT_KV_REQUIRER_APPLICATION_NAME,
        action_name="create-secret",
        key=secret_key,
        value=secret_value,
    )

    vault_kv_get_secret_results = run_action_on_leader(
        juju,
        VAULT_KV_REQUIRER_APPLICATION_NAME,
        action_name="get-secret",
        key=secret_key,
    )

    assert vault_kv_get_secret_results["value"] == secret_value
