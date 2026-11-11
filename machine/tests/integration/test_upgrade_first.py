import logging
from pathlib import Path

import jubilant
import pytest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    REFRESH_TIMEOUT,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault_and_wait,
    fast_forward,
    initialize_unseal_authorize_vault,
    refresh_application,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.18/stable"
CURRENT_TRACK_FIRST_STABLE_REVISION = 546


@pytest.mark.abort_on_fail
def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    juju: jubilant.Juju, vault_charm_path: Path
):
    logger.info("Deploying vault from Charmhub")
    deploy_vault_and_wait(
        juju,
        NUM_VAULT_UNITS,
        status="blocked",
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
    )
    _, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME) and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
        logger.info("Refreshing vault from built charm")
        refresh_application(juju, APP_NAME, vault_charm_path)

    logger.info("Waiting for vault to be blocked after refresh")
    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APP_NAME) and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=REFRESH_TIMEOUT,
    )

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, unseal_key)

        logger.info("Waiting for vault to be active after refresh")
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME) and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
