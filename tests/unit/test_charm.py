#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

import hcl  # type: ignore[import-untyped]
import requests
from botocore.response import StreamingBody
from charm import (
    AUTOUNSEAL_MOUNT_PATH,
    CHARM_POLICY_NAME,
    CHARM_POLICY_PATH,
    PKI_CSR_SECRET_LABEL,
    S3_RELATION_NAME,
    VAULT_CHARM_APPROLE_SECRET_LABEL,
    VaultCharm,
    config_file_content_matches,
)
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    ProviderCertificate,
)
from charms.vault_k8s.v0.vault_autounseal import (
    AutounsealDetails,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    Certificate,
    SecretsBackend,
    Token,
    Vault,
)
from charms.vault_k8s.v0.vault_s3 import S3Error
from charms.vault_k8s.v0.vault_tls import (
    CA_CERTIFICATE_JUJU_SECRET_LABEL,
    VaultCertsError,
    VaultTLSManager,
)
from ops import pebble, testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

S3_RELATION_LIB_PATH = "charms.data_platform_libs.v0.s3"
S3_LIB_PATH = "charms.vault_k8s.v0.vault_s3"
VAULT_KV_LIB_PATH = "charms.vault_k8s.v0.vault_kv"
TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
VAULT_AUTOUNSEAL_LIB_PATH = "charms.vault_k8s.v0.vault_autounseal"
VAULT_KV_RELATION_NAME = "vault-kv"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"


def read_file(path: str) -> str:
    """Read a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


class TestConfigFileContentMatches(unittest.TestCase):
    def test_given_identical_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)

    def test_given_different_vault_config_when_config_file_content_matches_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertFalse(matches)

    def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config_with_raft_peers.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers_equivalent.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)


class TestCharm(unittest.TestCase):
    patcher_vault_tls_manager = patch("charm.VaultTLSManager", autospec=VaultTLSManager)
    patcher_vault = patch("charm.Vault", autospec=Vault)

    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.mock_vault_tls_manager = TestCharm.patcher_vault_tls_manager.start().return_value
        self.mock_vault = TestCharm.patcher_vault.start().return_value

        self.model_name = "whatever"
        self.harness = testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_model_name(name=self.model_name)
        self.harness.begin()
        self.container_name = "vault"
        self.app_name = "vault-k8s"

    def tearDown(self):
        TestCharm.patcher_vault_tls_manager.stop()
        TestCharm.patcher_vault.stop()
        # TestCharm.patcher_vault_autounseal_requires.stop()

    def get_valid_s3_params(self):
        """Return a valid S3 parameters for mocking."""
        return {
            "bucket": "BUCKET",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "http://ENDPOINT",
            "region": "REGION",
        }

    def _set_peer_relation(self) -> int:
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(relation_name="vault-peers", remote_app=self.app_name)

    def _set_approle_secret(self, role_id: str, secret_id: str) -> None:
        """Set the approle secret."""
        content = {
            "role-id": role_id,
            "secret-id": secret_id,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)

    def _set_ca_certificate_secret(self, private_key: str, certificate: str) -> None:
        """Set the certificate secret."""
        content = {
            "certificate": certificate,
            "privatekey": private_key,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)

    def _set_csr_secret_in_peer_relation(self, relation_id: int, csr: str) -> None:
        """Set the csr secret in the peer relation."""
        content = {
            "csr": csr,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=PKI_CSR_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)
        key_values = {"vault-pki-csr-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def setup_vault_kv_relation(self) -> tuple:
        app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        unit_name = app_name + "/0"
        relation_name = VAULT_KV_RELATION_NAME

        host_ip = "10.20.20.1"
        self.harness.add_network(host_ip, endpoint="vault-kv")
        self.harness.set_leader()
        rel_id = self.harness.add_relation(relation_name, app_name)
        unit_name = app_name + "/0"
        egress_subnet = "10.20.20.20/32"
        self.harness.add_relation_unit(rel_id, unit_name)
        self.harness.update_relation_data(
            rel_id, unit_name, {"egress_subnet": egress_subnet, "nonce": "0"}
        )

        return (rel_id, egress_subnet)

    # Test install
    @patch("ops.model.Container.remove_path")
    def test_given_can_connect_when_install_then_existing_data_is_removed(self, patch_remove_path):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_remove_path.assert_has_calls(
            calls=[
                call(path="/vault/raft/vault.db", recursive=False),
                call(path="/vault/raft/raft/raft.db", recursive=False),
            ]
        )

    # Test configure
    @patch("ops.model.Container.restart", new=Mock)
    @patch("socket.getfqdn")
    def test_given_peer_relation_created_when_configure_then_config_file_is_pushed(
        self,
        patch_socket_getfqdn,
    ):
        self.harness.set_leader(is_leader=True)
        patch_socket_getfqdn.return_value = "myhostname"
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="whatever role id",
            secret_id="whatever secret id",
        )
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        self.assertEqual(pushed_content_hcl, expected_content_hcl)

    @patch("ops.model.Container.restart", new=Mock)
    def test_given_peer_relation_created_when_configure_then_pebble_plan_is_set(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="whatever role id",
            secret_id="whatever secret id",
        )
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "vault server -config=/vault/config/vault.hcl",
                    "startup": "enabled",
                }
            },
        }
        self.assertEqual(
            self.harness.get_container_pebble_plan("vault").to_dict(),
            expected_plan,
        )

    @patch("ops.model.Container.restart", new=Mock)
    def test_given_all_prerequisites_when_configure_then_configure_completes(self):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="whatever role id",
            secret_id="whatever secret id",
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
            },
        )

        self.harness.charm.on.config_changed.emit()

        self.mock_vault.is_raft_cluster_healthy.assert_called_once()

    # Test collect status
    def test_given_cant_connect_when_evaluate_status_then_status_is_waiting(self):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_evaluate_status_then_status_is_waiting(self):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_bind_address_not_available_when_evaluate_status_then_status_is_waiting(
        self, mock_get_binding
    ):
        mock_get_binding.return_value = None
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for bind and ingress addresses to be available"),
        )

    @patch("charm.VaultCharm._ingress_address", new=PropertyMock(return_value="1.1.1.1"))
    @patch("ops.model.Container.restart", new=Mock)
    def test_given_storage_not_available_when_evaluate_status_then_status_is_waiting(
        self,
    ):
        self.mock_vault_tls_manager.tls_file_available_in_charm.return_value = False
        self.mock_vault_tls_manager.get_tls_file_path_in_charm.side_effect = VaultCertsError()

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for CA certificate to be accessible in the charm"),
        )

    @patch("charm.VaultCharm._ingress_address", new=PropertyMock(return_value="1.1.1.1"))
    @patch("ops.model.Container.restart", new=Mock)
    def test_given_ca_certificate_secret_not_set_when_evaluate_status_then_status_is_waiting(
        self,
    ):
        self.mock_vault_tls_manager.tls_file_available_in_charm.return_value = False

        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for CA certificate to be accessible in the charm"),
        )

    @patch("charm.VaultCharm._ingress_address", new=PropertyMock(return_value="1.1.1.1"))
    @patch("ops.model.Container.restart", new=Mock)
    def test_given_ca_certificate_not_pushed_to_workload_when_evaluate_status_then_status_is_waiting(
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self.mock_vault_tls_manager.tls_file_available_in_charm.return_value = False

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for CA certificate to be accessible in the charm"),
        )

    def test_given_vault_uninitialized_when_evaluate_status_then_status_is_blocked(self):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
            },
        )
        self._set_peer_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus("Please initialize Vault"),
        )

    def test_given_vault_is_sealed_when_evaluate_status_then_status_is_blocked(self):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": True,
                "needs_migration.return_value": False,
            },
        )
        self._set_peer_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus("Please unseal Vault"),
        )

    def test_given_no_approle_auth_secret_when_evaluate_status_then_status_is_blocked(self):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
            },
        )
        self._set_peer_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus("Please authorize charm (see `authorize-charm` action)"),
        )

    @patch("charm.VaultCharm._ingress_address", new=PropertyMock(return_value="1.1.1.1"))
    @patch("ops.model.Container.restart", new=Mock)
    def test_given_api_not_available_when_evaluate_status_then_status_is_waiting(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": False,
            },
        )

        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be available"),
        )

    def test_given_api_available_when_evaluate_status_then_status_is_blocked(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
            },
        )

        self._set_peer_relation()
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus("Please initialize Vault"),
        )

    def test_given_all_prerequisites_when_evaluate_status_then_status_is_active(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_sealed.return_value": False,
                "is_initialized.return_value": True,
            },
        )

        self._set_peer_relation()
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        self._set_approle_secret(role_id="role id", secret_id="secret id")

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ActiveStatus(),
        )

    # Test Authorize Charm
    def test_given_unit_is_leader_when_authorize_charm_then_approle_configured_and_secrets_stored(
        self,
    ):
        self.harness.set_leader()
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )

        self.mock_vault.configure_mock(
            **{
                "get_token_data.return_value": {"policies": ["root"]},
                "configure_approle.return_value": "approle_id",
                "generate_role_secret_id.return_value": "secret_id",
            },
        )

        action_result = self.harness.run_action("authorize-charm", {"token": "test-token"}).results

        self.mock_vault.authenticate.assert_called_once_with(Token("test-token"))
        self.mock_vault.enable_audit_device.assert_called_once_with(
            device_type=AuditDeviceType.FILE, path="stdout"
        )
        self.mock_vault.enable_approle_auth_method.assert_called_once()
        self.mock_vault.configure_policy.assert_called_once_with(
            policy_name=CHARM_POLICY_NAME, policy_path=CHARM_POLICY_PATH
        )
        self.mock_vault.configure_approle.assert_called_once_with(
            role_name="charm", policies=[CHARM_POLICY_NAME, "default"], cidrs=["10.0.0.10/24"]
        )
        self.mock_vault.generate_role_secret_id.assert_called_once_with(
            name="charm", cidrs=["10.0.0.10/24"]
        )

        secret_content = self.harness.model.get_secret(
            label=VAULT_CHARM_APPROLE_SECRET_LABEL
        ).get_content()

        assert secret_content["role-id"] == "approle_id"
        assert secret_content["secret-id"] == "secret_id"
        assert action_result["result"] == "Charm authorized successfully."

    def test_given_unit_is_not_leader_when_authorize_charm_then_action_fails(
        self,
    ):
        self.harness.set_leader(False)
        try:
            self.harness.run_action("authorize-charm", {"token": "test-token"})
        except testing.ActionFailed as e:
            self.assertEqual(e.message, "This action must be run on the leader unit.")

    def test_given_unit_is_leader_and_token_is_invalid_when_authorize_charm_then_action_fails(
        self,
    ):
        self.harness.set_leader()
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.harness.charm.app.name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )

        self.mock_vault.configure_mock(
            **{
                "get_token_data.return_value": None,
                "configure_approle.return_value": "approle_id",
                "generate_role_secret_id.return_value": "secret_id",
            },
        )

        try:
            self.harness.run_action("authorize-charm", {"token": "test-token"})
        except testing.ActionFailed as e:
            self.assertEqual(e.message, "The token provided is not valid.")

    # Test remove
    def test_given_can_connect_when_on_remove_then_raft_storage_path_is_deleted(self):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="vault-raft", attach=True)
        (root / "vault/raft/raft").mkdir(parents=True)
        (root / "vault/raft/vault.db").write_text("whatever vault content")
        (root / "vault/raft/raft/raft.db").write_text("whatever raft content")

        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.remove.emit()

        self.assertFalse((root / "vault/raft/vault.db").exists())
        self.assertFalse((root / "vault/raft/raft/raft.db").exists())

    def test_given_node_in_raft_when_on_remove_then_node_is_removed_from_raft(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": True,
                "get_num_raft_peers.return_value": 2,
                "is_sealed.return_value": False,
            },
        )

        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )

        self.harness.charm.on.remove.emit()

        self.mock_vault.remove_raft_node.assert_called_with(
            node_id=f"{self.model_name}-{self.app_name}/0"
        )

    def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": False,
            },
        )

        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )

        self.harness.charm.on.remove.emit()

        self.mock_vault.remove_raft_node.assert_not_called()

    @patch(
        "ops.model.Container.get_service",
        return_value=Mock(spec=pebble.ServiceInfo, **{"is_running.return_value": True}),
    )
    @patch("ops.model.Container.stop")
    def test_given_service_is_running_when_on_remove_then_service_is_stopped(
        self,
        patch_stop_service,
        patch_get_service,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": False,
            },
        )

        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )

        self.harness.charm.on.remove.emit()

        patch_stop_service.assert_called_with("vault")

    # Test S3
    def test_given_s3_relation_not_created_when_create_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(
            context.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    def test_given_unit_not_leader_when_create_backup_action_then_action_fails(self):
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(
            message="S3 pre-requisites not met. Only leader unit can perform backup operations."
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(
            context.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint):.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_s3_session_not_created_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_bucket_creation_raises_an_exception_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_create_bucket.return_value = False
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to create S3 bucket.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_bucket_creation_fails_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_create_bucket.return_value = False
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to create S3 bucket.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_vault_is_not_initialized_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
            },
        )

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to initialize Vault client.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_vault_api_not_available_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": False,
                "is_initialized.return_value": True,
            },
        )

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to initialize Vault client.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_vault_initialization_secret_not_available_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to initialize Vault client.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    def test_given_approle_secret_not_set_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to initialize Vault client.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    @patch(f"{S3_LIB_PATH}.S3.upload_content")
    def test_given_s3_content_upload_fails_when_create_backup_action_then_action_fails(
        self,
        patch_upload_content,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )

        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_create_bucket.return_value = True
        patch_upload_content.return_value = False
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("create-backup")

        self.assertEqual(context.exception.message, "Failed to upload backup to S3 bucket.")

    @patch(f"{S3_LIB_PATH}.S3.create_bucket")
    @patch(f"{S3_LIB_PATH}.S3.upload_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_content_uploaded_to_s3_when_create_backup_action_then_action_succeeds(
        self,
        patch_get_s3_connection_info,
        patch_upload_content,
        patch_create_bucket,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )

        patch_upload_content.return_value = True
        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        action_output = self.harness.run_action("create-backup")

        self.assertIn("backup-id", action_output.results)
        backup_id = action_output.results["backup-id"]
        self.assertIn(f"vault-backup-{self.model_name}", backup_id)

    def test_given_s3_relation_not_created_when_list_backups_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("list-backups")

        self.assertEqual(
            context.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_unit_not_leader_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("list-backups")

        self.assertEqual(
            context.exception.message,
            "S3 pre-requisites not met. Only leader unit can perform backup operations.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("list-backups")

        self.assertEqual(
            context.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint):.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("list-backups")

        self.assertEqual(context.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.get_object_key_list")
    def test_given_get_object_list_raises_an_exception_when_list_backups_action_then_action_fails(
        self,
        patch_get_object_key_list,
        patch_get_s3_connection_info,
    ):
        patch_get_object_key_list.side_effect = S3Error("Error listing objects")

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("list-backups")

        self.assertEqual(
            context.exception.message,
            "Failed to run list-backups action - Failed to list backups.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.get_object_key_list")
    def test_given_backups_in_s3_when_list_backups_action_then_action_succeeds_with_backup_list(
        self,
        patch_get_object_key_list,
        patch_get_s3_connection_info,
    ):
        patch_get_object_key_list.return_value = ["backup1", "backup2"]
        expected_backup_list = ["backup1", "backup2"]
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        action_output = self.harness.run_action("list-backups")

        self.assertEqual(action_output.results["backup-ids"], json.dumps(expected_backup_list))

    def test_given_s3_relation_not_created_when_restore_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params={"backup-id": "12345"})

        self.assertEqual(
            context.exception.message, "S3 pre-requisites not met. S3 relation not created."
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_unit_not_leader_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params={"backup-id": "12345"})

        self.assertEqual(
            context.exception.message,
            "S3 pre-requisites not met. Only leader unit can perform backup operations.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params={"backup-id": "12345"})

        self.assertEqual(
            context.exception.message,
            "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint):.",
        )

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params={"backup-id": "12345"})

        self.assertEqual(context.exception.message, "Failed to create S3 session.")

    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch(f"{S3_LIB_PATH}.S3.get_content")
    def test_given_get_content_raises_s3error_when_restore_backup_action_then_action_fails(
        self,
        patch_get_content,
        patch_get_s3_connection_info,
    ):
        patch_get_content.side_effect = S3Error("Random bucket related error message")

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params={"backup-id": "12345"})

        self.assertEqual(context.exception.message, "Failed to retrieve snapshot from S3 storage.")

    @patch(f"{S3_LIB_PATH}.S3.get_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_not_initialized_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_get_content,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": False,
            },
        )
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params=params)

        self.assertEqual(context.exception.message, "Failed to restore vault.")

    @patch(f"{S3_LIB_PATH}.S3.get_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_api_not_available_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_get_content,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": False,
            },
        )

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params=params)

        self.assertEqual(context.exception.message, "Failed to restore vault.")

    @patch(f"{S3_LIB_PATH}.S3.get_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_initialization_secret_not_available_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_get_content,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
            },
        )

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params=params)

        self.assertEqual(context.exception.message, "Failed to restore vault.")

    @patch(f"{S3_LIB_PATH}.S3.get_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_restoring_snapshot_fails_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        patch_get_content,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=500, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        with self.assertRaises(testing.ActionFailed) as context:
            self.harness.run_action("restore-backup", params=params)

        self.assertEqual(context.exception.message, "Failed to restore vault.")

    @patch(f"{S3_LIB_PATH}.S3.get_content")
    @patch(f"{S3_RELATION_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_snapshot_is_restored_when_restore_backup_action_then_action_succeeds(
        self,
        patch_get_s3_connection_info,
        patch_get_content,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=200, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        action_output = self.harness.run_action("restore-backup", params=params)

        self.assertEqual(action_output.results["restored"], "whatever backup id")

    # Test Vault KV
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_unit_credentials")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
    def test_given_unit_not_leader_when_new_vault_kv_client_attached_then_event_kv_relation_data_not_set(
        self,
        patch_set_vault_url,
        patch_set_mount,
        patch_set_ca_certificate,
        patch_audit_device_enabled,
    ):
        self.harness.set_leader(is_leader=False)
        self.harness.set_can_connect(container=self.container_name, val=True)
        vault_kv_relation_name = "vault-kv"
        vault_kv_relation_id = self.harness.add_relation(
            relation_name=vault_kv_relation_name, remote_app="vault-kv-remote"
        )
        self.harness.add_relation_unit(
            relation_id=vault_kv_relation_id, remote_unit_name="vault-kv-remote/0"
        )
        event = Mock()
        event.relation_id = vault_kv_relation_id
        self.harness.charm._on_new_vault_kv_client_attached(event)
        patch_set_vault_url.assert_not_called()
        patch_set_mount.assert_not_called()
        patch_set_ca_certificate.assert_not_called()
        patch_audit_device_enabled.assert_not_called()

    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_approle_auth_is_enabled(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_approle_secret(
            role_id="role id",
            secret_id="secret id",
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
        event.mount_suffix = "suffix"
        event.egress_subnet = "2.2.2.0/24"
        event.nonce = "123123"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        self.mock_vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
        )

    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_relation_data_is_set(
        self,
        set_vault_url,
        set_mount,
        set_ca_certificate,
    ):
        self.mock_vault.configure_mock(
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
        event.mount_suffix = "suffix"
        event.egress_subnet = "2.2.2.0/24"
        event.nonce = "123123"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        self.harness.get_relation_data(rel_id, self.app_name)
        set_vault_url.assert_called()
        set_mount.assert_called()
        set_ca_certificate.assert_called()

    def test_given_prerequisites_are_met_when_related_kv_client_unit_egress_is_updated_then_secret_content_is_updated(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )

        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        rel_id, egress_subnet = self.setup_vault_kv_relation()
        self.mock_vault.read_role_secret.return_value = {"cidr_list": [egress_subnet]}

        mount_suffix = "whatever-suffix"
        self.harness.update_relation_data(
            rel_id, VAULT_KV_REQUIRER_APPLICATION_NAME, {"mount_suffix": mount_suffix}
        )
        unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"

        with patch("ops.Secret.set_content") as set_content:
            self.harness.update_relation_data(
                rel_id, unit_name, {"egress_subnet": "10.20.20.240/32"}
            )
            assert set_content.call_count == 1

    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_mount_is_configured(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

        self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        event.params = {"relation_name": "relation", "relation_id": "99"}
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
        event.mount_suffix = "suffix"
        event.egress_subnet = "2.2.2.0/24"
        event.nonce = "123123"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        self.mock_vault.enable_secrets_engine.assert_called_with(
            SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
        )

    # Test PKI
    @patch("charm.get_common_name_from_certificate", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    def test_given_vault_is_available_when_tls_certificates_pki_relation_joined_then_certificate_request_is_made(
        self,
        patch_request_certificate_creation,
    ):
        csr = "some csr content"
        self.harness.update_config({"common_name": "vault"})
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "get_intermediate_ca.return_value": "vault",
                "generate_pki_intermediate_ca_csr.return_value": csr,
            },
        )
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )

        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        self.harness.add_relation_unit(relation_id, "tls-provider/0")

        self.mock_vault.enable_secrets_engine.assert_called_with(SecretsBackend.PKI, "charm-pki")
        self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
            mount="charm-pki", common_name="vault"
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=csr.encode(), is_ca=True
        )

    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki(
        self,
        patch_get_assigned_certificates,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_intermediate_ca_set.return_value": False,
                "is_pki_role_created.return_value": False,
            },
        )

        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        self.harness.update_config({"common_name": "vault"})
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )
        self._set_csr_secret_in_peer_relation(relation_id=peer_relation_id, csr="some csr content")
        event = CertificateAvailableEvent(
            handle=Mock(),
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca,
            chain=chain,
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )

        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name="tls-provider",
                csr=csr,
                certificate=certificate,
                ca=ca,
                chain=chain,
                revoked=False,
                expiry_time=datetime.now(timezone.utc),
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event=event)

        self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        self.mock_vault.create_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm"
        )

    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
    @patch("charm.get_common_name_from_csr")
    def test_given_vault_available_when_vault_pki_certificate_creation_request_then_certificate_is_provided(
        self,
        patch_get_common_name_from_csr,
        patch_set_relation_certificate,
    ):
        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_pki_role_created.return_value": True,
                "sign_pki_certificate_signing_request.return_value": Certificate(
                    certificate=certificate,
                    ca=ca,
                    chain=chain,
                ),
            },
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        common_name = "vault"
        relation_id = 99
        patch_get_common_name_from_csr.return_value = common_name
        self.harness.update_config({"common_name": common_name})
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_approle_secret(
            role_id="root token content",
            secret_id="whatever secret id",
        )

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request=csr,
            relation_id=relation_id,
            is_ca=False,
        )

        self.harness.charm._on_vault_pki_certificate_creation_request(event=event)

        self.mock_vault.sign_pki_certificate_signing_request.assert_called_with(
            mount="charm-pki",
            csr=csr,
            role="charm",
            common_name=common_name,
        )

        patch_set_relation_certificate.assert_called_with(
            relation_id=relation_id,
            certificate_signing_request=csr,
            certificate=certificate,
            ca=ca,
            chain=chain,
        )

    @patch("ops.testing._TestingPebbleClient.restart_services", new=MagicMock)
    @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealRequires.get_details")
    def test_given_autounseal_details_available_when_autounseal_details_ready_then_transit_stanza_generated(
        self,
        mock_get_details,
    ):
        # Given
        address = "some address"
        key_name = "some key"
        role_id = "role_id"
        secret_id = "secret_id"
        ca_cert = "ca_cert"
        mock_get_details.return_value = AutounsealDetails(
            address, key_name, role_id, secret_id, ca_cert
        )
        relation_id = self.harness.add_relation(
            relation_name="vault-autounseal-requires", remote_app="autounseal-provider"
        )
        self.harness.set_can_connect(self.container_name, True)
        self.harness.add_storage(storage_name="config", attach=True)
        self._set_peer_relation()
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values={},
        )
        self.mock_vault.token = "some token"

        # When
        self.harness.charm.vault_autounseal_requires.on.vault_autounseal_details_ready.emit(
            address, key_name, role_id, secret_id, ca_cert
        )

        # Then
        root = self.harness.get_filesystem_root(self.container_name)
        pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
        assert pushed_content_hcl["seal"]["transit"]["address"] == address
        assert pushed_content_hcl["seal"]["transit"]["token"] == "some token"
        assert pushed_content_hcl["seal"]["transit"]["key_name"] == "some key"
        self.mock_vault.authenticate.assert_called_with(AppRole(role_id, secret_id))
        self.mock_vault_tls_manager.push_autounseal_ca_cert.assert_called_with(ca_cert)

    @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealProvides.set_autounseal_data")
    def test_when_autounseal_initialize_then_credentials_are_set(self, mock_set_autounseal_data):
        # Given
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "create_autounseal_credentials.return_value": (
                    "key name",
                    "autounseal role id",
                    "autounseal secret id",
                ),
            },
        )
        self.harness.set_leader()
        self.harness.set_can_connect(self.container_name, True)
        relation_id = self.harness.add_relation(
            relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
        )
        relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)
        self._set_approle_secret("role id", "secret id")
        self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "ca cert"

        # When
        self.harness.charm.vault_autounseal_provides.on.vault_autounseal_initialize.emit(relation)

        # Then
        mock_set_autounseal_data.assert_called_once_with(
            relation,
            "https://10.0.0.10:8200",
            "key name",
            "autounseal role id",
            "autounseal secret id",
            "ca cert",
        )

    def test_when_autounseal_destroy_then_credentials_are_removed(self):
        # Given
        self.mock_vault.configure_mock(
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
            },
        )
        self._set_approle_secret("role id", "secret id")
        self.harness.set_leader()
        self.harness.set_can_connect(self.container_name, True)
        with self.harness.hooks_disabled():
            relation_id = self.harness.add_relation(
                relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
            )
            relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)

        # When
        self.harness.charm.vault_autounseal_provides.on.vault_autounseal_destroy.emit(relation)

        # Then
        self.mock_vault.destroy_autounseal_credentials.assert_called_once_with(
            relation_id, AUTOUNSEAL_MOUNT_PATH
        )
