# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
import time
from pathlib import Path

import jubilant
import pytest

from config import (
    APPLICATION_NAME,
    DEPLOY_TIMEOUT,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SHORT_TIMEOUT,
)
from helpers import (
    deploy_vault,
    fast_forward,
    get_ca_cert_file_location,
    initialize_unseal_authorize_vault,
    refresh_application,
    unseal_all_vault_units,
)

logger = logging.getLogger(__name__)

CURRENT_TRACK_LATEST_STABLE_CHANNEL = "1.19/stable"
CURRENT_TRACK_FIRST_STABLE_REVISION = 528
UPDATE_STATUS_HOOK_ERROR = 'hook failed: "update-status"'
WORKLOAD_PEBBLE_SOCKET = "/charm/containers/vault/pebble.socket"


def wait_for_vault_to_be_blocked(juju: jubilant.Juju) -> None:
    """Wait for the old charm to settle, retrying hooks that raced Pebble startup."""
    deadline = time.monotonic() + DEPLOY_TIMEOUT
    retried_units: set[str] = set()
    status = juju.status()
    while time.monotonic() < deadline:
        vault = status.apps.get(APPLICATION_NAME)
        if (
            vault
            and jubilant.all_blocked(status, APPLICATION_NAME)
            and len(vault.units) == NUM_VAULT_UNITS
        ):
            return

        if vault:
            for unit_name, unit in vault.units.items():
                if unit.workload_status.current != "error":
                    continue
                if unit.workload_status.message != UPDATE_STATUS_HOOK_ERROR:
                    raise RuntimeError(f"Unexpected error on {unit_name}: {unit.workload_status}")
                if unit_name in retried_units:
                    continue

                # Revision 528 does not handle update-status racing Pebble startup (#1047).
                try:
                    juju.cli("ssh", unit_name, "test", "-S", WORKLOAD_PEBBLE_SOCKET)
                except jubilant.CLIError:
                    continue

                logger.warning("Retrying failed update-status hook on %s", unit_name)
                juju.cli("resolved", unit_name)
                retried_units.add(unit_name)

        time.sleep(10)
        status = juju.status()

    raise TimeoutError(f"Vault did not reach blocked status within {DEPLOY_TIMEOUT}s\n{status}")


@pytest.mark.abort_on_fail
def test_given_first_stable_revision_in_track_when_refresh_then_status_is_active(
    juju: jubilant.Juju, vault_charm_path: Path
):
    logger.info("Deploying vault from Charmhub")
    deploy_vault(
        juju,
        num_units=NUM_VAULT_UNITS,
        channel=CURRENT_TRACK_LATEST_STABLE_CHANNEL,
        revision=CURRENT_TRACK_FIRST_STABLE_REVISION,
    )
    wait_for_vault_to_be_blocked(juju)
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APPLICATION_NAME)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
        logger.info("Refreshing vault from built charm")
        refresh_application(juju, APPLICATION_NAME, vault_charm_path)

    logger.info("Waiting for vault to be blocked after refresh")
    juju.wait(
        lambda s: (
            jubilant.all_blocked(s, APPLICATION_NAME)
            and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
        ),
        timeout=SHORT_TIMEOUT,
    )

    ca_file = get_ca_cert_file_location(juju, APPLICATION_NAME)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        unseal_all_vault_units(juju, unseal_key, root_token, ca_file)

        logger.info("Waiting for vault to be active after refresh")
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APPLICATION_NAME)
                and len(s.apps[APPLICATION_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
