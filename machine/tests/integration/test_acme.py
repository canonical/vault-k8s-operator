import logging
import time
from collections import namedtuple
from pathlib import Path

import jubilant
import pytest
import requests

from config import (
    APP_NAME,
    JUJU_FAST_INTERVAL,
    NUM_VAULT_UNITS,
    SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
    SELF_SIGNED_CERTIFICATES_CHANNEL,
    SELF_SIGNED_CERTIFICATES_REVISION,
    UNMATCHING_COMMON_NAME,
)
from helpers import (
    deploy_vault,
    fast_forward,
    get_leader_unit_name,
    get_unit_address,
    get_vault_token_and_unseal_key,
    has_relation,
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
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel=SELF_SIGNED_CERTIFICATES_CHANNEL,
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


def verify_acme_configured(juju: jubilant.Juju, app_name: str) -> bool:
    leader_name = get_leader_unit_name(juju, app_name)
    leader_ip = get_unit_address(juju, leader_name)
    url = f"https://{leader_ip}:8200/v1/charm-acme/acme/directory"

    retry_count = 12
    for attempt in range(retry_count):
        try:
            response = requests.get(url, verify=False)
            if response.status_code == 200 and "newNonce" in response.json():
                return True
        except (requests.RequestException, ValueError) as e:
            logger.warning("ACME check attempt %s/%s failed: %s", attempt + 1, retry_count, str(e))

        if attempt < retry_count - 1:
            fast_interval_in_seconds = int(JUJU_FAST_INTERVAL[:-1])
            time.sleep(fast_interval_in_seconds)

    return False


@pytest.mark.abort_on_fail
def test_given_tls_certificates_acme_relation_when_integrate_then_status_is_active_and_acme_configured(
    juju: jubilant.Juju, deploy: VaultInit
):
    common_name = UNMATCHING_COMMON_NAME
    common_name_config = {
        "acme_ca_common_name": common_name,
    }
    juju.config(APP_NAME, common_name_config)
    allow_any_name_config = {
        "acme_allow_any_name": "true",
    }
    juju.config(APP_NAME, allow_any_name_config)
    allow_subdomains_config = {
        "acme_allow_subdomains": "true",
    }
    juju.config(APP_NAME, allow_subdomains_config)
    if not has_relation(juju, APP_NAME, "tls-certificates-acme"):
        juju.integrate(
            f"{APP_NAME}:tls-certificates-acme",
            f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        )
    with fast_forward(juju, JUJU_FAST_INTERVAL):
        juju.wait(
            lambda s: (
                jubilant.all_active(s, APP_NAME)
                and jubilant.all_active(s, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME)
                and len(s.apps[APP_NAME].units) == NUM_VAULT_UNITS
            ),
            timeout=600,
        )
        # FIXME: This seems to rely on the reconcile loop -- at least in some
        # cases, so we wait in fast forward
        # https://warthogs.atlassian.net/browse/TLSENG-766
        assert verify_acme_configured(juju, APP_NAME)
