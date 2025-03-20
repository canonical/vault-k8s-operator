#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test charm for vault-kv."""

import logging
import secrets
from pathlib import Path
from typing import Any

from charms.vault_k8s.v0.vault_kv import (
    VaultKvConnectedEvent,
    VaultKvReadyEvent,
    VaultKvRequires,
)
from ops import main
from ops.charm import ActionEvent, CharmBase
from ops.framework import EventBase
from ops.model import ActiveStatus

from lib.juju_facade import JujuFacade, NoSuchStorageError
from vault_client import (
    Vault,  # type: ignore[import-not-found]
)

NONCE_SECRET_LABEL = "vault-kv-nonce"
VAULT_KV_SECRET_LABEL = "vault-kv"
VAULT_KV_SECRET_PATH = "test"
VAULT_CA_CERT_FILENAME = "ca.pem"


logger = logging.getLogger(__name__)


class VaultKVRequirerCharm(CharmBase):
    """Charm requiring vault-kv for testing."""

    def __init__(self, *args: Any):
        super().__init__(*args)
        self.vault_kv = VaultKvRequires(self, "vault-kv", mount_suffix="kv")
        self.juju_facade = JujuFacade(self)
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.vault_kv.on.connected, self._on_kv_connected)
        self.framework.observe(self.vault_kv.on.ready, self._on_kv_ready)
        self.framework.observe(self.on.create_secret_action, self._on_create_secret_action)
        self.framework.observe(self.on.get_secret_action, self._on_get_secret_action)

    def _configure(self, _: EventBase):
        """Create a secret to store the nonce."""
        self.juju_facade.set_app_secret_content(
            label=NONCE_SECRET_LABEL,
            content={"nonce": secrets.token_hex(16)},
        )
        self.unit.status = ActiveStatus()

    def _on_kv_connected(self, event: VaultKvConnectedEvent):
        """Request credentials from Vault KV."""
        egress_subnets = self.juju_facade.get_egress_subnets(
            event.relation_name, relation=event.relation
        )
        self.vault_kv.request_credentials(event.relation, egress_subnets, self.get_nonce())

    def _on_kv_ready(self, event: VaultKvReadyEvent):
        """Store the Vault KV credentials in a secret."""
        if not (relation := event.relation):
            return
        if not (ca_certificate := self.vault_kv.get_ca_certificate(relation)):
            logger.error("CA certificate not found")
            return
        if not (vault_url := self.vault_kv.get_vault_url(relation)):
            logger.error("Vault URL not found")
            return
        if not (mount := self.vault_kv.get_mount(relation)):
            logger.error("Mount not found")
            return
        unit_credentials = self.vault_kv.get_unit_credentials(relation)
        juju_secret_content = {
            "vault-url": vault_url,
            "mount": mount,
            "credentials-secret-id": unit_credentials,
        }
        self.juju_facade.set_app_secret_content(
            label=VAULT_KV_SECRET_LABEL, content=juju_secret_content
        )
        self._store_ca_certificate(cert=ca_certificate)

    def _store_ca_certificate(self, cert: str) -> None:
        """Store the CA certificate in the charm storage."""
        certs_path = self._get_ca_cert_location_in_charm()
        with open(f"{certs_path}/{VAULT_CA_CERT_FILENAME}", "w") as fd:
            fd.write(cert)

    def _on_create_secret_action(self, event: ActionEvent):
        """Create a secret in Vault KV."""
        if not self.juju_facade.secret_exists(label=VAULT_KV_SECRET_LABEL):
            event.fail("Vault KV secret not found")
            return
        kv_secret_content = self.juju_facade.get_latest_secret_content(label=VAULT_KV_SECRET_LABEL)
        mount = kv_secret_content["mount"]
        ca_certificate_path = self._get_ca_cert_location_in_charm()
        if ca_certificate_path is None:
            event.fail("CA certificate not found")
            return
        secret_key = event.params.get("key")
        secret_value = event.params.get("value")
        if not secret_key or not secret_value:
            event.fail("Missing key or value")
            return
        credentials_secret_content = self.juju_facade.get_latest_secret_content(
            id=kv_secret_content["credentials-secret-id"]
        )
        vault = Vault(
            url=kv_secret_content["vault-url"],
            approle_role_id=credentials_secret_content["role-id"],
            ca_certificate=f"{ca_certificate_path}/{VAULT_CA_CERT_FILENAME}",
            approle_secret_id=credentials_secret_content["role-secret-id"],
        )
        vault.create_secret_in_kv(
            path=VAULT_KV_SECRET_PATH, mount=mount, key=secret_key, value=secret_value
        )

    def _on_get_secret_action(self, event: ActionEvent) -> None:
        if not self.juju_facade.secret_exists(label=VAULT_KV_SECRET_LABEL):
            event.fail("Vault KV secret not found")
            return
        kv_secret_content = self.juju_facade.get_latest_secret_content(label=VAULT_KV_SECRET_LABEL)
        credentials_secret_content = self.juju_facade.get_latest_secret_content(
            id=kv_secret_content["credentials-secret-id"]
        )
        mount = kv_secret_content["mount"]
        ca_certificate_path = self._get_ca_cert_location_in_charm()
        if ca_certificate_path is None:
            event.fail("CA certificate not found")
            return
        secret_key = event.params.get("key")
        if not secret_key:
            event.fail("Missing key or value")
            return
        vault = Vault(
            url=kv_secret_content["vault-url"],
            approle_role_id=credentials_secret_content["role-id"],
            ca_certificate=f"{ca_certificate_path}/{VAULT_CA_CERT_FILENAME}",
            approle_secret_id=credentials_secret_content["role-secret-id"],
        )
        vault_secret = vault.get_secret_in_kv(path=VAULT_KV_SECRET_PATH, mount=mount)
        if secret_key not in vault_secret:
            event.fail("Secret not found")
            return
        event.set_results({"value": vault_secret[secret_key]})

    def get_nonce(self) -> str:
        """Get the nonce from the secret."""
        secret = self.model.get_secret(label=NONCE_SECRET_LABEL)
        return secret.get_content(refresh=True)["nonce"]

    def _get_ca_cert_location_in_charm(self) -> Path | None:
        """Return the CA certificate location in the charm (not in the workload).

        This path would typically be: /var/lib/juju/storage/certs/0/ca.pem

        Returns:
            Path: The CA certificate location

        Raises:
            VaultCertsError: If the CA certificate is not found
        """
        try:
            return self.juju_facade.get_storage_location("certs")
        except NoSuchStorageError:
            return None


if __name__ == "__main__":  # pragma: no cover
    main(VaultKVRequirerCharm)
