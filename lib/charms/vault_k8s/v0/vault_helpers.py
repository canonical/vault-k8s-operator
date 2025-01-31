"""This library contains helper function used when configuring the Vault service."""

import logging
from typing import Dict, List

import hcl
from charms.vault_k8s.v0.vault_managers import AutounsealConfigurationDetails
from jinja2 import Environment, FileSystemLoader

# The unique Charmhub library identifier, never change it
LIBID = "92129fe159114cf699a24f2e252795a0"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2

logger = logging.getLogger(__name__)


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
    autounseal_details: AutounsealConfigurationDetails | None = None,
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
        autounseal_address=autounseal_details.address if autounseal_details else None,
        autounseal_key_name=autounseal_details.key_name if autounseal_details else None,
        autounseal_mount_path=autounseal_details.mount_path if autounseal_details else None,
        autounseal_token=autounseal_details.token if autounseal_details else None,
        autounseal_tls_ca_cert=autounseal_details.ca_cert_path if autounseal_details else None,
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

    new_retry_joins = new_content_hcl["storage"]["raft"].pop("retry_join", [])

    try:
        existing_retry_joins = existing_config_hcl["storage"]["raft"].pop("retry_join", [])
    except KeyError:
        existing_retry_joins = []

    # If there is only one retry join, it is a dict
    if isinstance(new_retry_joins, dict):
        new_retry_joins = [new_retry_joins]
    if isinstance(existing_retry_joins, dict):
        existing_retry_joins = [existing_retry_joins]

    new_retry_join_api_addresses = {address["leader_api_addr"] for address in new_retry_joins}
    existing_retry_join_api_addresses = {
        address["leader_api_addr"] for address in existing_retry_joins
    }

    return (
        new_retry_join_api_addresses == existing_retry_join_api_addresses
        and new_content_hcl == existing_config_hcl
    )
