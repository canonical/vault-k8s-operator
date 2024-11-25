"""Library for managing Vault Charm features.

This library encapsulates the business logic for managing the Vault service and
its associated integrations within the context of our charms.
"""

# The unique Charmhub library identifier, never change it
import logging
from dataclasses import dataclass

from charms.vault_k8s.v0.juju_facade import JujuFacade
from charms.vault_k8s.v0.vault_autounseal import (
    AutounsealDetails,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_tls import File, VaultTLSManager
from ops import CharmBase, Model, Relation, SecretNotFoundError

LIBID = "4a8652e06ecb4eb28c5fdbf220d126bb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


AUTOUNSEAL_POLICY = """path "{mount}/encrypt/{key_name}" {{
    capabilities = ["update"]
}}

path "{mount}/decrypt/{key_name}" {{
    capabilities = ["update"]
}}
"""


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_managers"

    def process(self, msg, kwargs):
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})


@dataclass
class VaultAutounsealRelationDetails:
    """Computes the auto-unseal related values for a relation.

    This class is used to compute the static details for a vault-autounseal
    relation, such as the key name, policy name, and approle name. These values
    are all based on the relation ID.

    This class provides a central place to manage the naming conventions for
    the auto-unseal functionality.
    """

    relation: Relation

    @property
    def key_name(self) -> str:
        """Return the key name for the relation."""
        return str(self.relation.id)

    @property
    def policy_name(self) -> str:
        """Return the policy name for the relation."""
        return f"charm-autounseal-{self.relation.id}"

    @property
    def approle_name(self) -> str:
        """Return the approle name for the relation."""
        return f"charm-autounseal-{self.relation.id}"


class VaultAutounsealProviderManager:
    """Encapsulates the auto-unseal functionality.

    This class provides the business logic for auto-unseal functionality in
    Vault charms. It is opinionated, and aims to make the interface to enabling
    and managing the feature as simple as possible. Flexibility is sacrificed
    for simplicity.
    """

    def __init__(
        self,
        charm: CharmBase,
        juju_model: Model,
        client: VaultClient,
        provides: VaultAutounsealProvides,
        ca_cert: str,
        mount_path: str = "charm-autounseal",
    ):
        self._charm = charm
        self._juju_facade = JujuFacade(charm)
        self._model = juju_model
        self._client = client
        self._provides = provides
        self._mount_path = mount_path
        self._ca_cert = ca_cert
        self._port = 8200

        if not self._ca_cert:
            logger.warning("No CA certificate provided for auto-unseal")

    def get_address(self, relation: Relation) -> str:
        """Fetch the address from the relation and return it."""
        binding = self._model.get_binding(relation)
        if binding is None:
            raise VaultClientError("Failed to fetch binding from relation")
        return f"https://{binding.network.ingress_address}:{self._port}"

    @property
    def mount_path(self) -> str:
        """Return the mount path for the transit backend."""
        return self._mount_path

    def sync(self) -> None:
        """Ensure that all auto-unseal requests are fulfilled and clean up unused credentials.

        This looks for any outstanding requests for auto-unseal that may have
        been missed. If there are any, it generates the credentials and sets
        them in the relation databag.

        It also cleans up any credentials that are no longer used by any of the
        relations, and logs a warning about orphaned keys. It will not remove
        any keys, to prevent loss of data.
        """
        if not self._model.unit.is_leader():
            return
        outstanding_requests = self._provides.get_outstanding_requests()
        if outstanding_requests:
            self._client.ensure_secrets_engine(SecretsBackend.TRANSIT, self._mount_path)
        for relation in outstanding_requests:
            self.create_credentials(relation)

        self._clean_up_credentials()

    def _clean_up_credentials(self) -> None:
        """Clean up roles and policies that are no longer needed by autounseal.

        This method will remove any roles and policies that are no longer
        used by any of the existing relations. It will also detect any orphaned
        keys (keys that are not associated with any relation) and log a warning.
        """
        self._clean_up_roles()
        self._clean_up_policies()
        self._detect_orphaned_keys()

    def _detect_orphaned_keys(self) -> None:
        existing_keys = self._get_existing_keys()
        relation_key_names = [
            VaultAutounsealRelationDetails(relation).key_name
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        orphaned_keys = [key for key in existing_keys if key not in relation_key_names]
        if not orphaned_keys:
            return
        logging.warning(
            f"Orphaned autounseal keys were detected: {orphaned_keys}. If you are sure these are no longer needed, you may manually delete them using the vault CLI to suppress this message."
            " To delete a key, use the command `vault delete charm-autounseal/keys/<key_name>`."
        )
        for key_name in orphaned_keys:
            deletion_allowed = self._detect_if_deletion_allowed(key_name)
            if not deletion_allowed:
                self._allow_key_deletion(key_name)

    def _allow_key_deletion(self, key_name) -> None:
        logger.info("Allowing deletion of key %s", key_name)
        self._client.write(f"{self.mount_path}/keys/{key_name}/config", {"deletion_allowed": True})

    def _detect_if_deletion_allowed(self, key_name) -> bool:
        data = self._client.read(f"{self.mount_path}/keys/{key_name}")
        return data["deletion_allowed"]

    def _clean_up_roles(self) -> None:
        existing_roles = self._get_existing_roles()
        relation_role_names = [
            VaultAutounsealRelationDetails(relation).approle_name
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        for role in existing_roles:
            if role not in relation_role_names:
                logging.info("Removing unused role: %s", role)
                self._client.delete_role(role)

    def _clean_up_policies(self) -> None:
        existing_policies = self._get_existing_policies()
        relation_policy_names = [
            VaultAutounsealRelationDetails(relation).policy_name
            for relation in self._juju_facade.get_active_relations(self._provides.relation_name)
        ]
        for policy in existing_policies:
            if policy not in relation_policy_names:
                logging.info("Removing unused policy: %s", policy)
                self._client.delete_policy(policy)

    def _create_key(self, key_name) -> None:
        response = self._client.create_transit_key(mount_point=self.mount_path, key_name=key_name)
        logging.debug("Created a new autounseal key: %s", response)

    def create_credentials(self, relation: Relation) -> tuple[str, str, str]:
        """Create auto-unseal credentials for the given relation.

        Args:
            relation: The relation to create the credentials for.

        Returns:
            A tuple containing the key name, role ID, and secret ID.
        """
        relation_details = VaultAutounsealRelationDetails(relation)
        self._create_key(relation_details.key_name)
        policy_content = AUTOUNSEAL_POLICY.format(
            mount=self.mount_path, key_name=relation_details.key_name
        )
        self._client.create_or_update_policy(
            relation_details.policy_name,
            policy_content,
        )
        role_id = self._client.create_or_update_approle(
            relation_details.approle_name,
            policies=[relation_details.policy_name],
            token_period="60s",
        )
        secret_id = self._client.generate_role_secret_id(relation_details.approle_name)
        self._provides.set_autounseal_data(
            relation,
            self.get_address(relation),
            self.mount_path,
            relation_details.key_name,
            role_id,
            secret_id,
            self._ca_cert,
        )
        return relation_details.key_name, role_id, secret_id

    def _get_existing_keys(self) -> list[str]:
        return self._client.list(f"{self.mount_path}/keys")

    def _get_existing_roles(self) -> list[str]:
        output = self._client.list("auth/approle/role")
        return [role for role in output if role.startswith("charm-autounseal-")]

    def _get_existing_policies(self) -> list[str]:
        output = self._client.list("sys/policy")
        return [policy for policy in output if policy.startswith("charm-autounseal-")]


@dataclass
class AutounsealConfigurationDetails:
    """Credentials required for configuring auto-unseal on Vault."""

    address: str
    mount_path: str
    key_name: str
    token: str
    ca_cert_path: str


class VaultAutounsealRequirerManager:
    """Encapsulates the auto-unseal functionality from the Requirer Perspective.

    In other words, this manages the feature from the perspective of the Vault
    being auto-unsealed.
    """

    AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"

    def __init__(
        self,
        tls_manager: VaultTLSManager,
        model: Model,
        requires: VaultAutounsealRequires,
    ):
        self._tls_manager = tls_manager
        self._model = model
        self._requires = requires

    def vault_configuration_details(self) -> AutounsealConfigurationDetails | None:
        """Return the configuration details for the vault."""
        autounseal_details = self._requires.get_details()
        if not autounseal_details:
            return None
        self._tls_manager.push_autounseal_ca_cert(autounseal_details.ca_certificate)
        ca_cert_path = self._tls_manager.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA)
        return AutounsealConfigurationDetails(
            autounseal_details.address,
            autounseal_details.mount_path,
            autounseal_details.key_name,
            self._get_autounseal_vault_token(autounseal_details),
            ca_cert_path,
        )

    def _get_autounseal_vault_token(self, autounseal_details: AutounsealDetails) -> str:
        """Retrieve the auto-unseal Vault token, or generate a new one if required.

        Retrieves the last used token from Juju secrets, and validates that it
        is still valid. If the token is not valid, a new token is generated and
        stored in the Juju secret. A valid token is returned.

        Args:
            autounseal_details: The autounseal configuration details.

        Returns:
            A periodic Vault token that can be used for auto-unseal.

        """
        external_vault = VaultClient(
            url=autounseal_details.address,
            ca_cert_path=self._tls_manager.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA),
        )
        existing_token = self._get_juju_secret_field(self.AUTOUNSEAL_TOKEN_SECRET_LABEL, "token")
        # If we don't already have a token, or if the existing token is invalid,
        # authenticate with the AppRole details to generate a new token.
        if not existing_token or not external_vault.authenticate(Token(existing_token)):
            external_vault.authenticate(
                AppRole(autounseal_details.role_id, autounseal_details.secret_id)
            )
            # NOTE: This is a little hacky. If the token expires, every unit
            # will generate a new token, until the leader unit generates a new
            # valid token and sets it in the Juju secret.
            if self._model.unit.is_leader():
                self._set_juju_secret(
                    self.AUTOUNSEAL_TOKEN_SECRET_LABEL, {"token": external_vault.token}
                )
        return external_vault.token

    def _get_juju_secret_field(self, label: str, field: str) -> str | None:
        """Retrieve the latest revision of the secret content from Juju.

        Returns:
            The value of the field is returned, or `None` if the field does not
            exist.

            If the secret does not exist, `None` is returned.
        """
        try:
            juju_secret = self._model.get_secret(label=label)
        except SecretNotFoundError:
            return None
        content = juju_secret.get_content(refresh=True)
        return content.get(field)

    def _set_juju_secret(
        self, label: str, content: dict[str, str], description: str | None = None
    ) -> None:
        """Set the secret content at `label`, overwrite if it already exists.

        Args:
            label: The label of the secret.
            content: The content of the secret.
            description: The description of the secret.
        """
        try:
            secret = self._model.get_secret(label=label)
            secret.set_content(content)
        except SecretNotFoundError:
            self._model.app.add_secret(content, label=label, description=description)
