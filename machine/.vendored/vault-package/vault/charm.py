"""Common base class and constants for vault k8s and machine charms."""

import logging

import ops

from vault import juju_facade, vault_client, vault_managers
from vault.vault_client import VaultClient  # imported here to facilitate unittest.mock.patch

logger = logging.getLogger(__name__)

VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"


class VaultCharmBase(ops.CharmBase):
    """Common base class for vault k8s and machine charms."""

    juju_facade: juju_facade.JujuFacade
    tls: vault_managers.TLSManager

    @property
    def _api_address(self) -> str | None:
        raise NotImplementedError()

    def _on_authorize_charm_action(self, event: ops.ActionEvent) -> None:
        if not self.unit.is_leader():
            event.fail("This action must be run on the leader unit.")
            return

        secret_id = event.params.get("secret-id", "")
        try:
            token = self.juju_facade.get_latest_secret_content(id=secret_id).get("token", "")
            if not token:
                error = "Token not found in the secret"
                logger.warning("%s when authorizing charm.", error)
                event.fail(f"{error}. Please provide a valid token secret.")
                return
        except (juju_facade.NoSuchSecretError, juju_facade.SecretRemovedError):
            error = "The secret id provided could not be found by the charm"
            logger.warning("%s when authorizing charm.", error)
            event.fail(f"{error}. Please grant the token secret to the charm.")
            return

        logger.info("Authorizing the charm to interact with Vault")
        if not self._api_address:
            error = "API address is not available"
            logger.warning("%s when authorizing charm.", error)
            event.fail(f"{error}.")
            return
        if not self.tls.tls_file_available_in_charm(vault_managers.File.CA):
            event.fail("CA certificate is not available in the charm. Something is wrong.")
            return
        vault = VaultClient(
            self._api_address, self.tls.get_tls_file_path_in_charm(vault_managers.File.CA)
        )
        if not vault:
            error = "Failed to initialize the Vault client"
            logger.warning("%s when authorizing charm.", error)
            event.fail(f"{error}.")
            return
        if not vault.authenticate(vault_client.Token(token)):
            error = "The token provided is not valid"
            logger.error("%s when authorizing charm.", error)
            event.fail(f"{error}. Please use a Vault token with the appropriate permissions.")
            return

        role_name = "charm"
        policy_name = "charm-access"
        try:
            vault.enable_audit_device(device_type=vault_client.AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.create_or_update_policy_from_file(
                name=policy_name, path="src/templates/charm_policy.hcl"
            )
            role_id = vault.create_or_update_approle(
                name=role_name,
                policies=[policy_name, "default"],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            secret_id = vault.generate_role_secret_id(name=role_name)
        except vault_client.VaultClientError as e:
            error = "Vault returned an error while authorizing the charm"
            logger.exception("%s.", error)
            return event.fail(f"{error}: {str(e)}")
        self.juju_facade.set_app_secret_content(
            content={"role-id": role_id, "secret-id": secret_id},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
            description="The authentication details for the charm's access to vault.",
        )
        event.set_results(
            {"result": "Charm authorized successfully. You may now remove the secret."}
        )
