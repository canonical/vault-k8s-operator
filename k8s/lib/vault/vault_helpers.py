"""This library contains helper function used when configuring the Vault service."""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List

import hcl
from hvac.exceptions import VaultError
from jinja2 import Environment, FileSystemLoader
from requests.exceptions import RequestException

from vault.vault_client import VaultClient, VaultClientError

logger = logging.getLogger(__name__)

RELOADABLE_CONFIG_KEYS = frozenset({"log_level"})


class ConfigAction(Enum):
    """Action required for a running Vault to apply a configuration change."""

    NONE = "none"
    RELOAD = "reload"
    RESTART = "restart"


@dataclass
class AutounsealConfiguration:
    """Details required for configuring auto-unseal on Vault."""

    address: str
    mount_path: str
    key_name: str
    ca_cert_path: str


def common_name_config_is_valid(common_name: str) -> bool:
    """Return whether the config value for the common name is valid."""
    return common_name != ""


def render_vault_config_file(
    config_template_path: str,
    config_template_name: str,
    default_lease_ttl: str,
    max_lease_ttl: str,
    cluster_address: str,
    api_address: str,
    tls_cert_file: str,
    tls_key_file: str,
    tcp_address: str,
    raft_storage_path: str,
    node_id: str,
    retry_joins: List[Dict[str, str]],
    autounseal_config: AutounsealConfiguration | None = None,
) -> str:
    """Render the Vault config file."""
    jinja2_environment = Environment(loader=FileSystemLoader(config_template_path))
    template = jinja2_environment.get_template(config_template_name)
    content = template.render(
        default_lease_ttl=default_lease_ttl,
        max_lease_ttl=max_lease_ttl,
        cluster_address=cluster_address,
        api_address=api_address,
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
        tcp_address=tcp_address,
        raft_storage_path=raft_storage_path,
        node_id=node_id,
        retry_joins=retry_joins,
        autounseal_address=autounseal_config.address if autounseal_config else None,
        autounseal_mount_path=autounseal_config.mount_path if autounseal_config else None,
        autounseal_key_name=autounseal_config.key_name if autounseal_config else None,
        autounseal_ca_cert_path=autounseal_config.ca_cert_path if autounseal_config else None,
    )
    return content


def seal_type_has_changed(content_a: str, content_b: str) -> bool:
    """Check if the seal type has changed between two versions of the Vault configuration file.

    Currently only checks if the transit stanza is present or not, since this
    is all we support. This function will need to be extended to support
    alternate cases if and when we support them.
    """
    config_a = hcl.loads(content_a)
    config_b = hcl.loads(content_b)
    return _contains_transit_stanza(config_a) != _contains_transit_stanza(config_b)


def _contains_transit_stanza(config: dict) -> bool:
    return "seal" in config and "transit" in config["seal"]


def _split_retry_join_addresses(config: dict) -> tuple[dict, set[str]]:
    """Remove the retry_join stanzas from a parsed config and return their leader addresses."""
    retry_joins = config.get("storage", {}).get("raft", {}).pop("retry_join", [])
    # If there is only one retry join, it is a dict
    if isinstance(retry_joins, dict):
        retry_joins = [retry_joins]
    return config, {retry_join["leader_api_addr"] for retry_join in retry_joins}


def config_file_content_matches(existing_content: str, new_content: str) -> bool:
    """Return whether two Vault config file contents match.

    We check if the retry_join addresses match, and then we check if the rest of the config
    file matches.

    Returns:
        bool: Whether the vault config file content matches
    """
    existing_config_hcl = hcl.loads(existing_content)
    new_content_hcl = hcl.loads(new_content)
    if not existing_config_hcl:
        logger.info("Existing config file is empty")
        return existing_config_hcl == new_content_hcl
    if not new_content_hcl:
        logger.info("New config file is empty")
        return existing_config_hcl == new_content_hcl

    return _split_retry_join_addresses(existing_config_hcl) == _split_retry_join_addresses(
        new_content_hcl
    )


def get_config_action(
    existing_content: str, new_content: str, vault: VaultClient | None
) -> ConfigAction:
    """Return the action a running Vault needs to apply a configuration change.

    Vault reads retry_join only while it has no initialized local data and has not yet
    reached a leader. Once it has, Vault ignores retry_join, so a restart would only
    reseal it. The local Vault client is queried only when the decision depends on it.

    Raises:
        VaultClientError: If the decision depends on Vault's state and it can't be read.
    """
    existing_config, existing_addresses = _split_retry_join_addresses(hcl.loads(existing_content))
    new_config, new_addresses = _split_retry_join_addresses(hcl.loads(new_content))
    changed_keys = {
        key
        for key in existing_config.keys() | new_config.keys()
        if existing_config.get(key) != new_config.get(key)
    }
    if changed_keys - RELOADABLE_CONFIG_KEYS:
        return ConfigAction.RESTART
    if existing_addresses != new_addresses and _vault_uses_retry_join(vault):
        return ConfigAction.RESTART
    if changed_keys:
        return ConfigAction.RELOAD
    return ConfigAction.NONE


def _vault_uses_retry_join(vault: VaultClient | None) -> bool:
    """Return whether Vault is still trying to join a cluster using retry_join.

    Vault reports itself as initialized once it has initialized local data, has reached
    a leader and is waiting to be unsealed to complete the join, or has joined.

    Raises:
        VaultClientError: If Vault's initialization status can't be read.
    """
    if not vault or not vault.is_api_available():
        raise VaultClientError("Vault API is not available")
    try:
        return not vault.is_initialized()
    except (VaultError, RequestException) as e:
        raise VaultClientError(f"Failed to read Vault initialization status: {e}") from e
