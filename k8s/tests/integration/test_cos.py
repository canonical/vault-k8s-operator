# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    LOKI_APPLICATION_NAME,
    LOKI_REVISION,
    NUM_VAULT_UNITS,
    PROMETHEUS_APPLICATION_NAME,
    PROMETHEUS_REVISION,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
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
        root_token, key = get_vault_token_and_unseal_key(juju, APPLICATION_NAME)
        return VaultInit(root_token, key)
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_units=NUM_VAULT_UNITS,
    )
    juju.deploy(
        PROMETHEUS_APPLICATION_NAME,
        trust=True,
        channel="1/stable",
        revision=PROMETHEUS_REVISION,
    )
    juju.deploy(
        LOKI_APPLICATION_NAME,
        trust=True,
        channel="1/stable",
        revision=LOKI_REVISION,
    )
    juju.wait(
        lambda s: (
            APPLICATION_NAME in s.apps
            and PROMETHEUS_APPLICATION_NAME in s.apps
            and LOKI_APPLICATION_NAME in s.apps
            and jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        error=None,
    )
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)
    return VaultInit(root_token, unseal_key)


@pytest.mark.abort_on_fail
def test_given_prometheus_deployed_when_relate_vault_to_prometheus_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APPLICATION_NAME}:metrics-endpoint",
        f"{PROMETHEUS_APPLICATION_NAME}:metrics-endpoint",
    )
    juju.wait(
        lambda s: jubilant.all_active(s, APPLICATION_NAME, PROMETHEUS_APPLICATION_NAME),
        timeout=SHORT_TIMEOUT,
    )


@pytest.mark.abort_on_fail
def test_given_loki_deployed_when_relate_vault_to_loki_then_status_is_active(
    juju: jubilant.Juju, deploy: VaultInit
):
    juju.integrate(
        f"{APPLICATION_NAME}:logging",
        LOKI_APPLICATION_NAME,
    )
    juju.wait(
        lambda s: jubilant.all_active(s, APPLICATION_NAME, LOKI_APPLICATION_NAME),
        timeout=SHORT_TIMEOUT,
    )
