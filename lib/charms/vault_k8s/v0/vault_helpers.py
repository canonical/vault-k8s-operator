"""Common functions used by the vault charms."""

import logging
from typing import Dict, List

import hcl
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
)
from charms.vault_k8s.v0.juju_facade import (
    JujuFacade,
    NoSuchSecretError,
)
from charms.vault_k8s.v0.vault_client import AppRole
from charms.vault_k8s.v0.vault_managers import AutounsealConfigurationDetails
from jinja2 import Environment, FileSystemLoader
from ops.charm import CharmBase
from ops.model import Relation

# The unique Charmhub library identifier, never change it
LIBID = "92129fe159114cf699a24f2e252795a0"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


PEER_RELATION_NAME = "vault-peers"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
VAULT_PORT = 8200


class VaultHelpers:
    """Common functions used by the vault charms."""

    def __init__(self, charm: CharmBase):
        self.charm = charm
        self.juju_facade = JujuFacade(charm)

    def get_certificate_request(self) -> CertificateRequestAttributes | None:
        """Get the certificate request."""
        common_name = self.juju_facade.get_string_config("common_name")
        if not common_name:
            return None
        return CertificateRequestAttributes(
            common_name=common_name,
            is_ca=True,
        )

    def common_name_config_is_valid(self) -> bool:
        """Return whether the config value for the common name is valid."""
        common_name = self.juju_facade.get_string_config("common_name")
        return common_name != ""

    def get_relation_api_address(self, relation: Relation) -> str | None:
        """Fetch the api address from relation and returns it.

        Example: "https://10.152.183.20:8200"
        """
        if not (ingress_address := self.juju_facade.get_ingress_address(relation=relation)):
            return None
        return f"https://{ingress_address}:{VAULT_PORT}"

    def get_approle_auth_secret(self) -> AppRole | None:
        """Get the vault approle login details secret.

        Returns:
            AppRole: An AppRole object with role_id and secret_id set from the
                     values stored in the Juju secret, or None if the secret is
                     not found or either of the values are not set.
        """
        try:
            role_id, secret_id = self.juju_facade.get_secret_content_values(
                "role-id", "secret-id", label=VAULT_CHARM_APPROLE_SECRET_LABEL
            )
        except NoSuchSecretError:
            return None
        return AppRole(role_id, secret_id) if role_id and secret_id else None

    def set_approle_auth_secret(self, role_id: str, secret_id: str) -> None:
        """Set the vault approle login details secret."""
        self.juju_facade.set_app_secret_content(
            content={"role-id": role_id, "secret-id": secret_id},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
            description="The authentication details for the charm's access to vault.",
        )

    def remove_approle_auth_secret(self) -> None:
        """Remove the vault approle login details secret."""
        self.juju_facade.remove_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)

    def peer_relation_exists(self) -> bool:
        """Return whether the peer relation exists."""
        return self.juju_facade.relation_exists(PEER_RELATION_NAME)

    @property
    def bind_address(self) -> str | None:
        """Fetch the bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        return self.juju_facade.get_bind_address(relation_name=PEER_RELATION_NAME)

    @property
    def ingress_address(self) -> str | None:
        """Fetch the ingress address from peer relation and returns it.

        Returns:
            str: Ingress address
        """
        return self.juju_facade.get_ingress_address(PEER_RELATION_NAME)

    @property
    def node_id(self) -> str:
        """Return the node id for vault.

        Example of node id: "vault-k8s-0"
        """
        return f"{self.charm.model.name}-{self.charm.unit.name}"


def render_vault_config_file(
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
    """Render the vault config file."""
    jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR_PATH))
    template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
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
    existing_retry_joins = existing_config_hcl["storage"]["raft"].pop("retry_join", [])

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
