# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import unittest
from typing import List
from unittest.mock import Mock, patch

import ops
import ops.testing

from charm import VAULT_CERT_SECRET_LABEL, VaultCharm


class TestSendCaCert(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.harness = ops.testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin_with_initial_hooks()
        self.container_name = "vault"
        self.app_name = "vault-k8s"

    def _set_peer_relation(self) -> int:
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(relation_name="vault-peers", remote_app=self.app_name)

    def _set_initialization_secret_in_peer_relation(
        self, relation_id: int, root_token: str, unseal_keys: List[str]
    ) -> None:
        """Set the initialization secret in the peer relation."""
        content = {
            "roottoken": root_token,
            "unsealkeys": json.dumps(unseal_keys),
        }
        secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
        key_values = {"vault-initialization-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_certificate_secret_in_peer_relation(
        self, relation_id: int, certificate: str, private_key: str, ca_certificate: str
    ) -> None:
        """Set the certificate secret in the peer relation."""
        content = {
            "certificate": certificate,
            "privatekey": private_key,
            "cacertificate": ca_certificate,
        }
        secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
        key_values = {"vault-certificates-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    @patch("charm.config_file_content_matches", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("charm.generate_vault_certificates")
    def test_given_ca_cert_is_stored_when_relation_join_then_ca_cert_is_advertised(
        self,
        patch_generate_certs,
        patch_get_binding,
        patch_is_api_available,
        patch_vault_initialize,
    ):
        certificate = "certificate content"
        private_key = "private key content"
        ca_certificate = "ca certificate content"
        patch_generate_certs.return_value = private_key, certificate, ca_certificate
        patch_is_api_available.return_value = True
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.charm.on.install.emit()
        app = "traefik"
        rel_id = self.harness.add_relation(relation_name="send-ca-cert", remote_app=app)
        self.harness.add_relation_unit(relation_id=rel_id, remote_unit_name=f"{app}/0")
        secret = self.harness.charm.model.get_secret(label=VAULT_CERT_SECRET_LABEL).get_content()
        ca_from_secret = secret["cacertificate"]
        data = self.harness.get_relation_data(rel_id, self.harness.charm.unit)
        ca_from_rel_data = data["ca"]
        self.assertEqual(ca_from_secret, ca_from_rel_data)
