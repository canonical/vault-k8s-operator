#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime
import os
import tempfile
from unittest.mock import Mock, patch

import pytest
import scenario
from charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate
from charms.vault_k8s.v0.vault_tls import CA_CERTIFICATE_JUJU_SECRET_LABEL
from ops.model import WaitingStatus

from charm import VAULT_CHARM_APPROLE_SECRET_LABEL, VaultCharm

TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
CERTIFICATE_TRANSFER_LIB_PATH = "charms.certificate_transfer_interface.v0.certificate_transfer"
VAULT_TLS_PATH = "charms.vault_k8s.v0.vault_tls"


class TestCharmTLS:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=VaultCharm,
        )

    def test_given_not_leader_and_ca_not_set_when_evaluate_status_then_status_is_waiting(self):
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
            interface="vault-peer",
            peers_data={
                0: {"node_api_address": "http://5.2.1.9:8200"},
            },
        )
        vault_container = scenario.Container(
            name="vault",
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[vault_container],
            leader=False,
            relations=[peer_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for CA certificate to be accessible in the charm"
        )

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    def test_given_unit_is_leader_and_ca_certificate_not_generated_when_configure_then_ca_certificate_is_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {
                        "node_api_address": "http://1.2.3.4",
                    },
                },
            )
            certs_mount = scenario.Mount("/vault/certs", temp_dir)
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = scenario.Storage(
                name="certs",
            )
            config_storage = scenario.Storage(
                name="config",
            )
            state_in = scenario.State(
                containers=[vault_container],
                storage=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation],
            )

            state_out = self.ctx.run("update_status", state_in)

            # Assert the secret is created
            assert state_out.secrets[0].label == CA_CERTIFICATE_JUJU_SECRET_LABEL
            secret_content = state_out.secrets[0].contents[0]
            assert secret_content["privatekey"].startswith("-----BEGIN RSA PRIVATE KEY-----")
            assert secret_content["certificate"].startswith("-----BEGIN CERTIFICATE-----")

            # Assert the files are written to the correct location
            ca_cert_path = temp_dir + "/ca.pem"
            cert_path = temp_dir + "/cert.pem"
            private_key_path = temp_dir + "/key.pem"
            assert os.path.exists(ca_cert_path)
            assert os.path.exists(cert_path)
            assert os.path.exists(private_key_path)
            assert open(ca_cert_path).read().startswith("-----BEGIN CERTIFICATE-----")
            assert open(cert_path).read().startswith("-----BEGIN CERTIFICATE-----")
            assert open(private_key_path).read().startswith("-----BEGIN RSA PRIVATE KEY-----")

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    def test_given_certificate_access_relation_when_relation_joined_then_new_request_is_created(
        self, request_certificate_creation
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = scenario.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {
                        "node_api_address": "http://1.2.3.4",
                    },
                },
            )
            certs_mount = scenario.Mount("/vault/certs", temp_dir)
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = scenario.Storage(
                name="certs",
            )
            config_storage = scenario.Storage(
                name="config",
            )
            state_in = scenario.State(
                containers=[vault_container],
                relations=[certificates_relation, peer_relation],
                storage=[certs_storage, config_storage],
                leader=True,
            )

            self.ctx.run("update_status", state_in)

            request_certificate_creation.assert_called_once()

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch(
        f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3._find_certificate_in_relation_data"
    )
    def test_given_certificate_access_relation_when_cert_available_then_new_cert_saved(
        self, find_certificate_in_relation_data
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {
                        "node_api_address": "http://1.2.3.4",
                    },
                },
            )
            certificates_relation = scenario.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            find_certificate_in_relation_data.return_value = ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                ca="some ca",
                chain=["new cert"],
                certificate="some cert",
                revoked=False,
                expiry_time=datetime.datetime.now() + datetime.timedelta(days=1),
                application_name="some-tls-provider",
                csr="some csr",
            )
            certs_mount = scenario.Mount("/vault/certs", temp_dir)
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = scenario.Storage(
                name="certs",
            )
            config_storage = scenario.Storage(
                name="config",
            )
            state_in = scenario.State(
                containers=[vault_container],
                storage=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation, certificates_relation],
            )

            self.ctx.run("update_status", state_in)

            # Assert the file is created
            ca_cert_path = temp_dir + "/ca.pem"
            cert_path = temp_dir + "/cert.pem"
            assert os.path.exists(ca_cert_path)
            assert os.path.exists(cert_path)
            assert open(ca_cert_path).read().startswith("some ca")
            assert open(cert_path).read().startswith("some cert")

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch(f"{VAULT_TLS_PATH}.generate_certificate")
    def test_given_certificate_access_relation_when_relation_left_then_previous_state_restored(
        self, generate_certificate
    ):
        generate_certificate.return_value = b"self signed cert"
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {
                        "node_api_address": "http://1.2.3.4",
                    },
                },
            )
            certificates_relation = scenario.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            certs_mount = scenario.Mount("/vault/certs", temp_dir)
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = scenario.Storage(
                name="certs",
            )
            config_storage = scenario.Storage(
                name="config",
            )
            state_in = scenario.State(
                containers=[vault_container],
                storage=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation, certificates_relation],
            )

            self.ctx.run(certificates_relation.broken_event, state_in)

            # Assert the file is created
            ca_cert_path = temp_dir + "/cert.pem"
            assert os.path.exists(ca_cert_path)
            assert open(ca_cert_path).read() == "self signed cert"

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed")
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active_or_standby", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.authenticate", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available")
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch(f"{CERTIFICATE_TRANSFER_LIB_PATH}.CertificateTransferProvides.set_certificate")
    def test_given_ca_cert_exists_when_certificate_transfer_relation_joins_then_ca_cert_is_advertised(
        self, set_certificate, is_api_available, is_sealed
    ):
        is_api_available.return_value = True
        is_sealed.return_value = False
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write the CA cert to the temp dir
            ca_cert_path = temp_dir + "/ca.pem"
            cert_path = temp_dir + "/cert.pem"
            with open(ca_cert_path, "w") as f:
                f.write("some ca")
            with open(cert_path, "w") as f:
                f.write("some cert")
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {"node_api_address": "http://1.2.3.4"},
                },
            )
            cert_transfer_relation = scenario.Relation(
                endpoint="send-ca-cert",
                interface="certificate_transfer",
                remote_app_name="whatever",
            )
            certs_mount = scenario.Mount("/vault/certs", temp_dir)
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = scenario.Storage(
                name="certs",
            )
            config_storage = scenario.Storage(
                name="config",
            )
            approle_secret = scenario.Secret(
                id="0",
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                contents={0: {"role-id": "some role id", "secret-id": "some secret"}},
                owner="app",
            )
            ca_certificate_secret = scenario.Secret(
                id="1",
                label=CA_CERTIFICATE_JUJU_SECRET_LABEL,
                contents={0: {"privatekey": "some private key", "certificate": "some cert"}},
                owner="app",
            )
            state_in = scenario.State(
                containers=[vault_container],
                storage=[certs_storage, config_storage],
                secrets=[approle_secret, ca_certificate_secret],
                leader=True,
                relations=[peer_relation, cert_transfer_relation],
            )

            self.ctx.run(cert_transfer_relation.joined_event, state_in)

            set_certificate.assert_called_once_with(
                certificate="",
                ca="some ca",
                chain=[],
                relation_id=cert_transfer_relation.relation_id,
            )

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed")
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active_or_standby", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.authenticate", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available")
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch(f"{CERTIFICATE_TRANSFER_LIB_PATH}.CertificateTransferProvides.set_certificate")
    def test_given_ca_cert_is_not_stored_when_certificate_transfer_relation_joins_then_ca_cert_is_not_advertised(
        self, set_certificate, is_api_available, is_sealed
    ):
        is_api_available.return_value = True
        is_sealed.return_value = False
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                peers_data={
                    0: {"node_api_address": "http://1.2.3.4"},
                },
            )
            cert_transfer_relation = scenario.Relation(
                endpoint="send-ca-cert",
                interface="certificate_transfer",
                remote_app_name="whatever",
            )
            config_mount = scenario.Mount("/vault/config", temp_dir)
            vault_container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "config": config_mount,
                },
            )
            config_storage = scenario.Storage(
                name="config",
            )
            approle_secret = scenario.Secret(
                id="0",
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                contents={0: {"role-id": "some role id", "secret-id": "some secret"}},
                owner="app",
            )
            state_in = scenario.State(
                containers=[vault_container],
                storage=[config_storage],
                secrets=[approle_secret],
                leader=True,
                relations=[peer_relation, cert_transfer_relation],
            )

            self.ctx.run(cert_transfer_relation.joined_event, state_in)

            set_certificate.assert_not_called()
