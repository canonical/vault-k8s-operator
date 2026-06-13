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
    SELF_SIGNED_CERTIFICATES_REVISION,
)
from helpers import (
    ActionFailedError,
    authorize_charm,
    deploy_vault,
    fast_forward,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
    initialize_vault_leader,
    wait_for_status_message,
)

logger = logging.getLogger(__name__)

VaultInit = namedtuple("VaultInit", ["root_token", "unseal_key"])


@pytest.fixture(scope="module")
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool) -> VaultInit:
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
        channel="1/stable",
        revision=SELF_SIGNED_CERTIFICATES_REVISION,
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and jubilant.all_blocked(s, APP_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1000,
        )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated(
    juju: jubilant.Juju, deploy: VaultInit, vault_charm_path: Path
):
    # Arrange
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.deploy(
            vault_charm_path,
            "vault-b",
            trust=True,
            num_units=1,
        )
        juju.wait(
            lambda s: (
                "vault-b" in s.apps
                and jubilant.all_blocked(s, "vault-b")
                and len(s.apps["vault-b"].units) == 1
            ),
            timeout=600,
        )

    juju.integrate(
        "vault-b:tls-certificates-access",
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )

    # Act
    juju.integrate(f"{APP_NAME}:vault-autounseal-provides", "vault-b:vault-autounseal-requires")
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                "vault-b" in s.apps
                and jubilant.all_blocked(s, "vault-b")
                and len(s.apps["vault-b"].units) == 1
            ),
            timeout=300,
        )

        wait_for_status_message(
            juju=juju,
            count=1,
            expected_message="Please initialize Vault",
            app_name="vault-b",
        )

        root_token, recovery_key = initialize_vault_leader(juju, "vault-b")
        wait_for_status_message(
            juju=juju,
            count=1,
            expected_message="Please authorize charm (see `authorize-charm` action)",
            app_name="vault-b",
        )
        try:
            authorize_charm(juju, root_token, "vault-b")
        except ActionFailedError:
            logger.warning("Failed to authorize charm")

    # Assert
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 1,
            timeout=300,
        )


@pytest.mark.abort_on_fail
def test_given_vault_b_is_deployed_and_autounsealed_when_add_unit_then_status_is_active(
    juju: jubilant.Juju,
):
    assert len(juju.status().apps["vault-b"].units) == 1
    juju.add_unit("vault-b", num_units=1)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, "vault-b") and len(s.apps["vault-b"].units) == 2,
            timeout=300,
        )
