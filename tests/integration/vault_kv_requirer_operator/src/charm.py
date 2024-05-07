#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import secrets
from pathlib import Path
from typing import Optional

from charms.vault_k8s.v0.vault_kv import (
    VaultKvConnectedEvent,
    VaultKvReadyEvent,
    VaultKvRequires,
)
from ops.charm import ActionEvent, CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, SecretNotFoundError
from vault_client import Vault  # type: ignore[import-not-found]

NONCE_SECRET_LABEL = "vault-kv-nonce"
VAULT_KV_SECRET_LABEL = "vault-kv"
VAULT_KV_SECRET_PATH = "test"
VAULT_CA_CERT_FILENAME = "ca.pem"


logger = logging.getLogger(__name__)


class VaultKVRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.vault_kv = VaultKvRequires(self, "vault-kv", mount_suffix="kv")
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.vault_kv.on.connected, self._on_kv_connected)
        self.framework.observe(self.vault_kv.on.ready, self._on_kv_ready)
        self.framework.observe(self.on.create_secret_action, self._on_create_secret_action)
        self.framework.observe(self.on.get_secret_action, self._on_get_secret_action)

    def _configure(self, event: EventBase):
        """Create a secret to store the nonce."""
        try:
            self.model.get_secret(label=NONCE_SECRET_LABEL)
        except SecretNotFoundError:
            self.unit.add_secret(
            {"nonce": secrets.token_hex(16)},
            label=NONCE_SECRET_LABEL,
            description="Nonce for vault-kv relation",
        )
        self.unit.status = ActiveStatus()

    def _on_kv_connected(self, event: VaultKvConnectedEvent):
        """Request credentials from Vault KV."""
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        if not relation:
            return
        binding = self.model.get_binding(relation)
        if not binding:
            logger.error("Binding not found")
            return
        egress_subnet = str(binding.network.interfaces[0].subnet)
        self.vault_kv.request_credentials(relation, egress_subnet, self.get_nonce())

    def _on_kv_ready(self, event: VaultKvReadyEvent):
        """Store the Vault KV credentials in a secret."""
        if (relation := self.model.get_relation(event.relation_name, event.relation_id)) is None:
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
        secret = self.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content(refresh=True)
        juju_secret_content = {
            "vault-url": vault_url,
            "mount": mount,
            "role-id": secret_content["role-id"],
            "role-secret-id": secret_content["role-secret-id"],
        }
        try:
            vault_kv_secret = self.model.get_secret(label=VAULT_KV_SECRET_LABEL)
            vault_kv_secret.set_content(content=juju_secret_content)
            logger.info("Vault KV secret updated")
        except SecretNotFoundError:
            self.app.add_secret(juju_secret_content, label=VAULT_KV_SECRET_LABEL)
            logger.info("Vault KV secret created")
        self._store_ca_certificate(cert=ca_certificate)

    def _store_ca_certificate(self, cert: str) -> None:
        """Store the CA certificate in the charm storage."""
        certs_path = self._get_ca_cert_location_in_charm()
        with open(f"{certs_path}/{VAULT_CA_CERT_FILENAME}", "w") as fd:
            fd.write(cert)

    def _on_create_secret_action(self, event: ActionEvent):
        """Create a secret in Vault KV."""
        try:
            secret = self.model.get_secret(label=VAULT_KV_SECRET_LABEL)
        except SecretNotFoundError:
            event.fail("Vault KV secret not found")
            return
        secret_content = secret.get_content(refresh=True)
        mount = secret_content["mount"]
        ca_certificate_path = self._get_ca_cert_location_in_charm()
        if ca_certificate_path is None:
            event.fail("CA certificate not found")
            return
        secret_key = event.params.get("key")
        secret_value = event.params.get("value")
        if not secret_key or not secret_value:
            event.fail("Missing key or value")
            return
        vault = Vault(
            url=secret_content["vault-url"],
            approle_role_id=secret_content["role-id"],
            ca_certificate=f"{ca_certificate_path}/{VAULT_CA_CERT_FILENAME}",
            approle_secret_id=secret_content["role-secret-id"],
        )
        vault.create_secret_in_kv(
            path=VAULT_KV_SECRET_PATH, mount=mount, key=secret_key, value=secret_value
        )

    def _on_get_secret_action(self, event: ActionEvent) -> None:
        try:
            secret = self.model.get_secret(label=VAULT_KV_SECRET_LABEL)
        except SecretNotFoundError:
            event.fail("Vault KV secret not found")
            return
        secret_content = secret.get_content(refresh=True)
        mount = secret_content["mount"]
        ca_certificate_path = self._get_ca_cert_location_in_charm()
        if ca_certificate_path is None:
            event.fail("CA certificate not found")
            return
        secret_key = event.params.get("key")
        if not secret_key:
            event.fail("Missing key or value")
            return
        vault = Vault(
            url=secret_content["vault-url"],
            approle_role_id=secret_content["role-id"],
            ca_certificate=f"{ca_certificate_path}/{VAULT_CA_CERT_FILENAME}",
            approle_secret_id=secret_content["role-secret-id"],
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

    def _get_ca_cert_location_in_charm(self) -> Optional[Path]:
        """Return the CA certificate location in the charm (not in the workload).

        This path would typically be: /var/lib/juju/storage/certs/0/ca.pem

        Returns:
            Path: The CA certificate location

        Raises:
            VaultCertsError: If the CA certificate is not found
        """
        storage = self.model.storages
        if "certs" not in storage:
            return None
        if len(storage["certs"]) == 0:
            return None
        cert_storage = storage["certs"][0]
        return cert_storage.location


if __name__ == "__main__":  # pragma: no cover
    main(VaultKVRequirerCharm)
