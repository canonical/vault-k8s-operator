#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from io import StringIO
from typing import List
from unittest.mock import Mock, call, patch

from ops import testing
from ops.model import ActiveStatus, ModelError, WaitingStatus

from charm import VaultCharm


class MockNetwork:
    def __init__(self, bind_address: str):
        self.bind_address = bind_address


class MockBinding:
    def __init__(self, bind_address: str):
        self.network = MockNetwork(bind_address=bind_address)


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.model_name = "whatever"
        self.harness = testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_model_name(name=self.model_name)
        self.harness.begin()
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

    def _set_other_node_api_address_in_peer_relation(self, relation_id: int, unit_name: str):
        """Set the other node api address in the peer relation."""
        key_values = {"node_api_address": "http://5.2.1.9:8200"}
        self.harness.update_relation_data(
            app_or_unit=unit_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    @patch("ops.model.Container.remove_path")
    def test_given_can_connect_to_workload_when_install_then_existing_data_is_removed(
        self, patch_remove_path
    ):
        self.harness.set_leader(is_leader=False)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_remove_path.assert_has_calls(
            calls=[call(path="/vault/raft/vault.db"), call(path="/vault/raft/raft/raft.db")]
        )

    def test_given_cant_connect_to_workload_when_install_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_install_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation to be created"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_bind_address_not_available_when_install_then_status_is_waiting(
        self, patch_get_binding
    ):
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.side_effect = ModelError()

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for bind address to be available"),
        )

    @patch("ops.model.Container.push", new=Mock)
    @patch("vault.Vault.unseal")
    @patch("vault.Vault.set_token")
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Model.get_binding")
    def test_given_binding_address_when_install_then_vault_is_initialized(
        self,
        patch_get_binding,
        patch_is_api_available,
        patch_vault_initialize,
        patch_vault_set_token,
        patch_vault_unseal,
    ):
        root_token = "root token content"
        unseal_keys = ["unseal key 1"]
        bind_address = "1.2.1.2"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        patch_is_api_available.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_vault_initialize.return_value = root_token, unseal_keys
        self._set_peer_relation()
        self.harness.charm.on.install.emit()

        patch_vault_initialize.assert_called_once()
        patch_vault_set_token.assert_called_once_with(token=root_token)
        patch_vault_unseal.assert_called_once_with(unseal_keys=unseal_keys)

    @patch("ops.model.Container.push", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.set_token", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Model.get_binding")
    def test_given_binding_address_when_install_then_pebble_is_planned(
        self, patch_get_binding, patch_is_api_available, patch_vault_initialize
    ):
        bind_address = "1.2.1.2"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        patch_is_api_available.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self._set_peer_relation()

        expected_vault_config = {
            "ui": True,
            "storage": {
                "raft": {"path": "/vault/raft", "node_id": f"{self.model_name}-{self.app_name}/0"}
            },
            "listener": {
                "tcp": {
                    "address": "[::]:8200",
                    "tls_cert_file": "/vault/certs/cert.pem",
                    "tls_key_file": "/vault/certs/key.pem",
                }
            },
            "default_lease_ttl": "168h",
            "max_lease_ttl": "720h",
            "disable_mlock": True,
            "cluster_addr": f"https://{bind_address}:8201",
            "api_addr": f"https://{bind_address}:8200",
        }
        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        "VAULT_LOCAL_CONFIG": json.dumps(expected_vault_config),
                        "VAULT_API_ADDR": "https://[::]:8200",
                    },
                }
            },
        }
        self.harness.charm.on.install.emit()

        updated_plan = self.harness.get_container_pebble_plan("vault").to_dict()
        self.assertEqual(updated_plan, expected_plan)

    @patch("ops.model.Container.push", new=Mock)
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Model.get_binding")
    def test_given_vault_not_available_when_install_then_status_is_waiting(
        self, patch_get_binding, patch_is_api_available
    ):
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        patch_is_api_available.return_value = False

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be available"),
        )

    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("charm.generate_vault_certificates")
    def test_given_can_connect_when_install_then_certificate_secret_stored_in_peer_relation(
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
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        patch_is_api_available.return_value = True
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        relation_id = self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.app_name
        )
        self.assertIn("vault-certificates-secret-id", relation_data)
        secret_id = relation_data["vault-certificates-secret-id"]
        secret = self.harness.model.get_secret(id=secret_id)
        secret_content = secret.get_content()
        self.assertEqual(secret_content["certificate"], certificate)
        self.assertEqual(secret_content["privatekey"], private_key)
        self.assertEqual(secret_content["cacertificate"], ca_certificate)

    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.push")
    @patch("ops.model.Model.get_binding")
    @patch("charm.generate_vault_certificates")
    def test_given_can_connect_when_install_then_certificate_pushed_to_workload(
        self,
        patch_generate_certs,
        patch_get_binding,
        patch_push,
        patch_is_api_available,
        patch_vault_initialize,
    ):
        certificate = "certificate content"
        private_key = "private key content"
        ca_certificate = "ca certificate content"
        patch_generate_certs.return_value = private_key, certificate, ca_certificate
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        patch_is_api_available.return_value = True
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_push.assert_has_calls(
            calls=[
                call(path="/vault/certs/cert.pem", source=certificate),
                call(path="/vault/certs/key.pem", source=private_key),
                call(path="/vault/certs/ca.pem", source=ca_certificate),
            ]
        )

    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.push")
    @patch("ops.model.Model.get_binding")
    @patch("charm.generate_vault_certificates")
    def test_given_certificates_pushed_when_install_then_certificate_not_pushed_to_workload(
        self,
        patch_generate_certs,
        patch_get_binding,
        patch_push,
        patch_pull,
        patch_exists,
        patch_is_api_available,
        patch_vault_initialize,
    ):
        certificate = "certificate content"
        private_key = "private key content"
        ca_certificate = "ca certificate content"
        patch_exists.return_value = True
        patch_pull.side_effect = [
            StringIO(certificate),
            StringIO(private_key),
            StringIO(ca_certificate),
        ]
        patch_generate_certs.return_value = private_key, certificate, ca_certificate
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        patch_is_api_available.return_value = True
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_push.assert_not_called()

    def test_given_cant_connect_to_workload_when_config_changed_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_config_changed_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation"),
        )

    def test_given_initialization_secret_not_stored_when_config_changed_then_status_is_waiting(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault initialization secret"),
        )

    def test_given_other_node_api_addresses_not_available_when_config_changed_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=False)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal key content"],
        )

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for other units to provide their addresses"),
        )

    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.is_initialized")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_initialization_secret_is_stored_when_config_changed_then_pebble_plan_is_applied(
        self,
        patch_is_api_available,
        patch_is_initialized,
        patch_vault_is_sealed,
        patch_get_binding,
    ):
        bind_address = "1.2.3.4"
        patch_vault_is_sealed.return_value = False
        patch_is_api_available.return_value = True
        patch_is_initialized.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal key content"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="certificate content",
            private_key="private key content",
            ca_certificate="ca certificate content",
        )
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)

        self.harness.charm.on.config_changed.emit()

        expected_vault_config = {
            "ui": True,
            "storage": {
                "raft": {"path": "/vault/raft", "node_id": f"{self.model_name}-{self.app_name}/0"},
            },
            "listener": {
                "tcp": {
                    "address": "[::]:8200",
                    "tls_cert_file": "/vault/certs/cert.pem",
                    "tls_key_file": "/vault/certs/key.pem",
                }
            },
            "default_lease_ttl": "168h",
            "max_lease_ttl": "720h",
            "disable_mlock": True,
            "cluster_addr": f"https://{bind_address}:8201",
            "api_addr": f"https://{bind_address}:8200",
        }
        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        "VAULT_LOCAL_CONFIG": json.dumps(expected_vault_config),
                        "VAULT_API_ADDR": "https://[::]:8200",
                    },
                }
            },
        }
        self.assertEqual(
            self.harness.get_container_pebble_plan("vault").to_dict(),
            expected_plan,
        )

    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.is_initialized")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_initialization_secret_is_stored_when_config_changed_then_status_is_active(
        self,
        patch_is_api_available,
        patch_is_initialized,
        patch_vault_is_sealed,
        patch_get_binding,
    ):
        patch_vault_is_sealed.return_value = False
        patch_is_api_available.return_value = True
        patch_is_initialized.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal key content"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="certificate content",
            private_key="private key content",
            ca_certificate="ca certificate content",
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.unseal")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.is_initialized")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_vault_is_sealed_when_config_changed_then_vault_is_unsealed(
        self,
        patch_is_api_available,
        patch_is_initialized,
        patch_vault_is_sealed,
        patch_vault_unseal,
        patch_get_binding,
    ):
        patch_is_api_available.return_value = True
        patch_is_initialized.return_value = True
        unseal_keys = ["unseal key content"]
        patch_vault_is_sealed.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=unseal_keys,
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="certificate content",
            private_key="private key content",
            ca_certificate="ca certificate content",
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        patch_vault_unseal.assert_called_once_with(unseal_keys=unseal_keys)

    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_vault_api_not_available_when_config_changed_then_status_is_waiting(
        self, patch_is_api_available, patch_get_binding
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = False
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.app_name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="certificate content",
            private_key="private key content",
            ca_certificate="ca certificate content",
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id,
            unit_name=other_unit_name,
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be available"),
        )

    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized")
    @patch("vault.Vault.is_api_available")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_vault_is_not_initialized_when_config_changed_then_status_is_waiting(
        self, patch_is_api_available, patch_is_initialized, patch_get_binding
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_initialized.return_value = False
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.app_name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="certificate content",
            private_key="private key content",
            ca_certificate="ca certificate content",
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id,
            unit_name=other_unit_name,
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be initialized"),
        )

    def test_given_vault_certificate_not_available_when_config_changed_then_status_is_waiting(
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault certificate to be available"),
        )

    @patch("ops.model.Container.push")
    def test_given_vault_certificate_available_when_config_changed_then_pushed_to_workload(
        self, patch_push
    ):
        certificate = "certificate content"
        private_key = "private key content"
        ca_certificate = "ca certificate content"
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate=certificate,
            private_key=private_key,
            ca_certificate=ca_certificate,
        )

        self.harness.charm.on.config_changed.emit()

        patch_push.assert_has_calls(
            calls=[
                call(path="/vault/certs/cert.pem", source=certificate),
                call(path="/vault/certs/key.pem", source=private_key),
                call(path="/vault/certs/ca.pem", source=ca_certificate),
            ]
        )

    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.push")
    def test_given_certificates_already_pushed_when_config_changed_then_not_pushed(
        self,
        patch_push,
        patch_pull,
        patch_exists,
    ):
        patch_exists.return_value = True
        certificate = "certificate content"
        private_key = "private key content"
        ca_certificate = "ca certificate content"
        patch_pull.side_effect = [
            StringIO(certificate),
            StringIO(private_key),
            StringIO(ca_certificate),
        ]
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate=certificate,
            private_key=private_key,
            ca_certificate=ca_certificate,
        )

        self.harness.charm.on.config_changed.emit()

        patch_push.assert_not_called()

    @patch("ops.model.Container.remove_path")
    def test_given_can_connect_when_on_remove_then_raft_storage_path_is_deleted(
        self, patch_remove_path
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.remove.emit()

        patch_remove_path.assert_has_calls(
            calls=[call(path="/vault/raft/vault.db"), call(path="/vault/raft/raft/raft.db")]
        )

    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.get_num_raft_peers")
    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node")
    @patch("ops.model.Container.remove_path", new=Mock)
    def test_given_node_in_raft_when_on_remove_then_node_is_removed_from_raft(
        self,
        patch_remove_raft_node,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
        patch_get_num_raft_peers,
        patch_get_binding,
    ):
        patch_get_num_raft_peers.return_value = 2
        bind_address = "1.2.3.4"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = True
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_remove_raft_node.assert_called_with(node_id=f"{self.model_name}-{self.app_name}/0")

    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node")
    @patch("ops.model.Container.remove_path", new=Mock)
    def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
        self,
        patch_remove_raft_node,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = False
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_remove_raft_node.assert_not_called()

    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node", new=Mock)
    @patch("ops.model.Container.get_service", new=Mock)
    @patch("ops.model.Container.stop")
    @patch("ops.model.Container.remove_path", new=Mock)
    def test_given_service_is_running_when_on_remove_then_service_is_stopped(
        self,
        patch_stop_service,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = False
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_stop_service.assert_called_with("vault")
