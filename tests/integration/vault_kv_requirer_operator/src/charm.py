#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import secrets

from charms.vault_k8s.v0.vault_kv import (
    VaultKvConnectedEvent,
    VaultKvReadyEvent,
    VaultKvRequires,
)
from ops.charm import ActionEvent, CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, SecretNotFoundError

from vault import Vault

NONCE_SECRET_LABEL = "vault-kv-nonce"
VAULT_KV_SECRET_LABEL = "vault-kv"


class VaultKVRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.vault_kv = VaultKvRequires(self, "vault-kv", mount_suffix="kv")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.vault_kv.on.connected, self._on_kv_connected)
        self.framework.observe(self.vault_kv.on.ready, self._on_kv_ready)
        self.framework.observe(self.on.create_secret_action, self._on_create_secret_action)

    def _on_install(self, event: InstallEvent):
        self.unit.add_secret(
            {"nonce": secrets.token_hex(16)},
            label=NONCE_SECRET_LABEL,
            description="Nonce for vault-kv relation",
        )
        self.unit.status = ActiveStatus()

    def _on_kv_connected(self, event: VaultKvConnectedEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        egress_subnet = str(self.model.get_binding(relation).network.interfaces[0].subnet)
        self.vault_kv.request_credentials(relation, egress_subnet, self.get_nonce())

    def _on_kv_ready(self, event: VaultKvReadyEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        if relation is None:
            return
        unit_credentials = self.vault_kv.get_unit_credentials(relation)
        secret = self.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content()
        juju_secret_content = {
            "vault-url": self.vault_kv.get_vault_url(relation),
            "ca-certificate": self.vault_kv.get_ca_certificate(relation),
            "mount": self.vault_kv.get_mount(relation),
            "role-id": secret_content["role-id"],
            "role-secret-id": secret_content["role-secret-id"],
        }
        self.app.add_secret(juju_secret_content, label=VAULT_KV_SECRET_LABEL)

    def _on_create_secret_action(self, event: ActionEvent):
        try:
            secret = self.model.get_secret(label=VAULT_KV_SECRET_LABEL)
        except SecretNotFoundError:
            event.fail("Vault KV secret not found")
            return
        secret_content = secret.get_content()
        mount = secret_content["mount"]
        vault = Vault(
            url=secret_content["vault-url"],
            ca_certificate=secret_content["ca-certificate"],
            approle_role_id=secret_content["role-id"],
            approle_secret_id=secret_content["role-secret-id"],
        )
        vault.create_secret_in_kv(mount=mount, key="my-secret", value="my-value")

    def get_nonce(self) -> str:
        secret = self.model.get_secret(label=NONCE_SECRET_LABEL)
        return secret.get_content()["nonce"]


if __name__ == "__main__":  # pragma: no cover
    main(VaultKVRequirerCharm)
