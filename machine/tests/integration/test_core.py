import logging
from pathlib import Path

import jubilant
import pytest

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    REFRESH_TIMEOUT,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SHORT_TIMEOUT,
)
from helpers import (
    _get_arch,
    deploy_vault,
    fast_forward,
    get_ca_cert_file_location,
    get_leader_unit_address,
    get_leader_unit_name,
    get_vault_client,
    get_vault_token_and_unseal_key,
    initialize_unseal_authorize_vault,
)
from vault_helpers import Vault

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def deploy(juju: jubilant.Juju, vault_charm_path: Path, skip_deploy: bool):
    """Build and deploy the application."""
    if skip_deploy:
        logger.info("Skipping deployment due to --no-deploy flag")
        return
    deploy_vault(
        juju,
        charm_path=vault_charm_path,
        num_vaults=NUM_VAULT_UNITS,
    )
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="1/stable",
        revision={"amd64": 586, "arm64": 585}[_get_arch()],
        constraints={"arch": _get_arch()},
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


@pytest.mark.abort_on_fail
def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(  # noqa: E501
    juju: jubilant.Juju,
    deploy: None,
):
    """To test that Vault is actually running when the charm is active."""
    juju.integrate(
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        f"{APP_NAME}:tls-certificates-access",
    )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
                and all(u.juju_status.current == "idle" for u in s.apps[APP_NAME].units.values())
            ),
            timeout=600,
        )
    vault_ip = get_leader_unit_address(juju)
    vault_url = f"https://{vault_ip}:8200"
    ca_file_location = get_ca_cert_file_location(juju)
    assert ca_file_location
    vault = Vault(url=vault_url, ca_file_location=ca_file_location)
    assert not vault.is_initialized()


@pytest.mark.abort_on_fail
def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    juju: jubilant.Juju,
    deploy: None,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    ca_file_location = get_ca_cert_file_location(juju)
    root_token, unseal_key = initialize_unseal_authorize_vault(juju, APP_NAME)
    leader_name = get_leader_unit_name(juju, APP_NAME)

    vault = get_vault_client(juju, leader_name, root_token, ca_file_location)
    vault.wait_for_raft_nodes(expected_num_nodes=NUM_VAULT_UNITS)


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_scale_up_then_status_is_active(
    juju: jubilant.Juju,
    deploy: None,
):
    root_token, unseal_key = get_vault_token_and_unseal_key(juju, APP_NAME)

    num_units = NUM_VAULT_UNITS + 1
    old_unit_names = set(juju.status().apps[APP_NAME].units.keys())
    juju.add_unit(APP_NAME, num_units=1)

    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                len(s.apps[APP_NAME].units) == num_units
                and all(u.public_address for u in s.apps[APP_NAME].units.values())
                and any(
                    u.workload_status.message == "Please unseal Vault"
                    for u in s.apps[APP_NAME].units.values()
                )
            ),
            timeout=REFRESH_TIMEOUT,
        )

    new_unit_names = set(juju.status().apps[APP_NAME].units.keys()) - old_unit_names
    new_unit_name = new_unit_names.pop()
    ca_file_location = get_ca_cert_file_location(juju)
    vault = get_vault_client(juju, new_unit_name, root_token, ca_file_location)
    vault.unseal(unseal_key=unseal_key)
    vault.wait_for_node_to_be_unsealed()
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: jubilant.all_active(s, APP_NAME),
            timeout=SHORT_TIMEOUT,
        )

    vault.wait_for_raft_nodes(expected_num_nodes=num_units)


@pytest.mark.abort_on_fail
def test_given_application_is_deployed_when_scale_down_then_status_is_active(
    juju: jubilant.Juju,
    deploy: None,
):
    # Machine charms require a specific unit name to remove, not --num-units
    status = juju.status()
    unit_to_remove = sorted(status.apps[APP_NAME].units.keys())[-1]
    juju.remove_unit(unit_to_remove)
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME) and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=SHORT_TIMEOUT,
        )
    # Note: We are not verifying the number of nodes in the raft cluster
    # because the Vault API address is often not available during the
    # unit removal.
