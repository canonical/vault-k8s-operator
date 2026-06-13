import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APP_NAME,
    GRAFANA_AGENT_APPLICATION_NAME,
    GRAFANA_AGENT_REVISION,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    fast_forward,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
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
        GRAFANA_AGENT_APPLICATION_NAME,
        GRAFANA_AGENT_APPLICATION_NAME,
        base="ubuntu@24.04",
        channel="1/stable",
        revision=GRAFANA_AGENT_REVISION,
    )

    # When waiting for Vault to go to the blocked state, we may need an update
    # status event to recognize that the API is available, so we wait in
    # fast-forward.
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_blocked(s, APP_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=1000,
        )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APP_NAME}:cos-agent",
        f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME),
            timeout=SHORT_TIMEOUT,
        )
