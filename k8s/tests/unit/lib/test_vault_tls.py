#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import tempfile
from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch

import ops.testing as testing
import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    ProviderCertificate,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.model import WaitingStatus
from vault.vault_managers import CA_CERTIFICATE_JUJU_SECRET_LABEL

from charm import VAULT_CHARM_APPROLE_SECRET_LABEL, VaultCharm

TLS_CERTIFICATES_LIB_PATH_V3 = "charms.tls_certificates_interface.v3.tls_certificates"
TLS_CERTIFICATES_LIB_PATH_V4 = "charms.tls_certificates_interface.v4.tls_certificates"
CERTIFICATE_TRANSFER_LIB_PATH = "charms.certificate_transfer_interface.v1.certificate_transfer"
VAULT_MANAGERS_PATH = "vault.vault_managers"
VAULT_CA_SUBJECT = "Vault self signed CA"


class TestCharmTLS:
    patcher_get_assigned_certificate = patch(
        f"{TLS_CERTIFICATES_LIB_PATH_V4}.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    patcher_socket_get_fqdn = patch("socket.getfqdn")

    @pytest.fixture(autouse=True)
    def setup(self):
        self.fqdn = "my-fqdn"
        self.mock_get_assigned_certificate = TestCharmTLS.patcher_get_assigned_certificate.start()
        self.mock_get_fqdn = TestCharmTLS.patcher_socket_get_fqdn.start()
        self.mock_get_fqdn.return_value = self.fqdn

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=VaultCharm,
        )

    def test_given_not_leader_and_ca_not_set_when_evaluate_status_then_status_is_waiting(self):
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
            interface="vault-peer",
            local_unit_data={"node_api_address": "http://5.2.1.9:8200"},
        )
        vault_container = testing.Container(
            name="vault",
            can_connect=True,
        )
        state_in = testing.State(
            containers=[vault_container],
            leader=False,
            relations=[peer_relation],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for CA certificate to be accessible in the charm"
        )

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    def test_given_unit_is_leader_and_ca_certificate_not_generated_when_configure_then_ca_certificate_is_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation],
            )

            state_out = self.ctx.run(self.ctx.on.update_status(), state_in)

            # Assert the secret is created
            secret_content = state_out.get_secret(
                label=CA_CERTIFICATE_JUJU_SECRET_LABEL
            ).tracked_content
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

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    def test_given_certificate_access_relation_when_relation_changed_then_new_request_is_created(
        self,
    ):
        self.mock_get_assigned_certificate.return_value = None, None
        ingress_address = "1.2.3.4"
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            state_in = testing.State(
                containers=[vault_container],
                relations=[certificates_relation, peer_relation],
                storages=[certs_storage, config_storage],
                leader=True,
                networks={
                    testing.Network(
                        "vault-peers",
                        bind_addresses=[testing.BindAddress([testing.Address("192.0.2.1")])],
                        ingress_addresses=[ingress_address],
                    )
                },
            )

            self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

            self.mock_get_assigned_certificate.assert_called_once_with(
                certificate_request=CertificateRequestAttributes(
                    common_name=ingress_address,
                    sans_dns=frozenset({self.fqdn}),
                    sans_ip=frozenset({ingress_address}),
                    sans_oid=frozenset(),
                    email_address=None,
                    organization=None,
                    organizational_unit=None,
                    country_name=None,
                    state_or_province_name=None,
                    locality_name=None,
                    is_ca=False,
                )
            )

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    def test_given_certificate_access_relation_and_config_values_when_relation_changed_then_new_request_is_created_with_config_values(  # noqa: E501
        self,
    ):
        self.mock_get_assigned_certificate.return_value = None, None
        ingress_address = "1.2.3.4"
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            state_in = testing.State(
                containers=[vault_container],
                relations=[certificates_relation, peer_relation],
                storages=[certs_storage, config_storage],
                leader=True,
                networks={
                    testing.Network(
                        "vault-peers",
                        bind_addresses=[testing.BindAddress([testing.Address("192.0.2.1")])],
                        ingress_addresses=[ingress_address],
                    )
                },
                config={
                    "access_sans_dns": "mydomain.com,mydomain.org",
                    "access_country_name": "US",
                    "access_state_or_province_name": "California",
                    "access_locality_name": "San Francisco",
                    "access_organization": "My Organization",
                    "access_organizational_unit": "My Organizational Unit",
                    "access_email_address": "my@email.com",
                },
            )

            self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

            self.mock_get_assigned_certificate.assert_called_once_with(
                certificate_request=CertificateRequestAttributes(
                    common_name=ingress_address,
                    sans_dns=frozenset({self.fqdn, "mydomain.com", "mydomain.org"}),
                    sans_ip=frozenset({ingress_address}),
                    sans_oid=frozenset(),
                    email_address="my@email.com",
                    organization="My Organization",
                    organizational_unit="My Organizational Unit",
                    country_name="US",
                    state_or_province_name="California",
                    locality_name="San Francisco",
                    is_ca=False,
                )
            )

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    def test_given_certificate_access_relation_when_cert_available_then_new_cert_saved(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certificates_relation = testing.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            private_key = generate_private_key()
            ca_private_key = generate_private_key()
            ca_certificate = generate_ca(
                common_name="ca",
                private_key=ca_private_key,
                validity=timedelta(days=365),
            )
            csr = generate_csr(
                private_key=private_key,
                common_name="my.domain",
            )
            certificate = generate_certificate(
                csr=csr,
                ca=ca_certificate,
                ca_private_key=ca_private_key,
                validity=timedelta(days=365),
            )
            provider_certificate = ProviderCertificate(
                certificate_signing_request=csr,
                relation_id=certificates_relation.id,
                certificate=certificate,
                ca=ca_certificate,
                chain=[ca_certificate],
                revoked=False,
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation, certificates_relation],
            )

            self.ctx.run(self.ctx.on.relation_changed(certificates_relation), state_in)

            # Assert the file is created
            ca_cert_path = temp_dir + "/ca.pem"
            cert_path = temp_dir + "/cert.pem"
            assert os.path.exists(ca_cert_path)
            assert os.path.exists(cert_path)
            assert open(ca_cert_path).read() == str(ca_certificate)
            assert open(cert_path).read() == str(certificate)

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    @patch(f"{VAULT_MANAGERS_PATH}.generate_certificate")
    def test_given_certificate_access_relation_when_relation_left_then_previous_state_restored(
        self, patch_generate_certificate: MagicMock
    ):
        private_key = generate_private_key()
        ca_private_key = generate_private_key()
        ca_certificate = generate_ca(
            common_name="ca",
            private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        csr = generate_csr(
            private_key=private_key,
            common_name="my.domain",
        )
        certificate = generate_certificate(
            csr=csr,
            ca=ca_certificate,
            ca_private_key=ca_private_key,
            validity=timedelta(days=365),
        )
        patch_generate_certificate.return_value = certificate
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certificates_relation = testing.Relation(
                endpoint="tls-certificates-access",
                interface="tls-certificates",
                remote_app_name="some-tls-provider",
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                leader=True,
                relations=[peer_relation, certificates_relation],
            )

            self.ctx.run(self.ctx.on.relation_broken(certificates_relation), state_in)

            # Assert the file is created
            ca_cert_path = temp_dir + "/cert.pem"
            assert os.path.exists(ca_cert_path)
            assert open(ca_cert_path).read() == str(certificate)

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    def test_given_self_signed_certificates_already_created_when_update_status_then_new_certificates_are_not_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            ca_certificate_secret = testing.Secret(
                label=CA_CERTIFICATE_JUJU_SECRET_LABEL,
                tracked_content={"privatekey": "some private key", "certificate": "some cert"},
                owner="app",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                secrets=[ca_certificate_secret],
                leader=True,
                relations=[peer_relation],
            )
            private_key = generate_private_key()
            ca_private_key = generate_private_key()
            ca_certificate = generate_ca(
                common_name=VAULT_CA_SUBJECT,
                private_key=ca_private_key,
                validity=timedelta(days=365),
            )
            csr = generate_csr(
                private_key=private_key,
                common_name="my.domain",
            )
            certificate = generate_certificate(
                csr=csr,
                ca=ca_certificate,
                ca_private_key=ca_private_key,
                validity=timedelta(days=365),
            )
            with open(temp_dir + "/ca.pem", "w") as f:
                f.write(str(ca_certificate))

            with open(temp_dir + "/cert.pem", "w") as f:
                f.write(str(certificate))

            self.ctx.run(self.ctx.on.update_status(), state_in)

            with open(temp_dir + "/ca.pem", "r") as f:
                assert f.read() == str(ca_certificate)
            with open(temp_dir + "/cert.pem", "r") as f:
                assert f.read() == str(certificate)
            modification_time_cert_pem = os.stat(temp_dir + "/cert.pem").st_mtime
            modification_time_ca_pem = os.stat(temp_dir + "/ca.pem").st_mtime
            assert os.stat(temp_dir + "/cert.pem").st_mtime == modification_time_cert_pem
            assert os.stat(temp_dir + "/ca.pem").st_mtime == modification_time_ca_pem

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    @patch(f"{VAULT_MANAGERS_PATH}.generate_ca")
    @patch(f"{VAULT_MANAGERS_PATH}.generate_certificate")
    def test_given_tls_relation_removed_when_configure_self_signed_certificates_then_certs_are_overwritten(
        self, patch_generate_certificate: MagicMock, patch_generate_ca: MagicMock
    ):
        self_signed_private_key = generate_private_key()
        self_signed_ca_private_key = generate_private_key()
        self_signed_ca_certificate = generate_ca(
            common_name=VAULT_CA_SUBJECT,
            private_key=self_signed_ca_private_key,
            validity=timedelta(days=365),
        )
        self_signed_csr = generate_csr(
            private_key=self_signed_private_key,
            common_name="my.domain",
        )
        self_signed_certificate = generate_certificate(
            csr=self_signed_csr,
            ca=self_signed_ca_certificate,
            ca_private_key=self_signed_ca_private_key,
            validity=timedelta(days=365),
        )
        patch_generate_ca.return_value = self_signed_ca_certificate
        patch_generate_certificate.return_value = self_signed_certificate

        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )

            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                secrets=[],
                leader=True,
                relations=[peer_relation],
            )
            tls_integration_private_key = generate_private_key()
            tls_integration_ca_private_key = generate_private_key()
            tls_integration_ca_certificate = generate_ca(
                common_name="tls integration ca",
                private_key=tls_integration_ca_private_key,
                validity=timedelta(days=365),
            )
            tls_integration_csr = generate_csr(
                private_key=tls_integration_private_key,
                common_name="my.domain",
            )
            tls_integration_certificate = generate_certificate(
                csr=tls_integration_csr,
                ca=tls_integration_ca_certificate,
                ca_private_key=tls_integration_ca_private_key,
                validity=timedelta(days=365),
            )
            with open(temp_dir + "/ca.pem", "w") as f:
                f.write(str(tls_integration_ca_certificate))
            with open(temp_dir + "/cert.pem", "w") as f:
                f.write(str(tls_integration_certificate))

            self.ctx.run(self.ctx.on.update_status(), state_in)

            with open(temp_dir + "/ca.pem", "r") as f:
                assert f.read() == str(self_signed_ca_certificate)
            with open(temp_dir + "/cert.pem", "r") as f:
                assert f.read() == str(self_signed_certificate)

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available", new=Mock)
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    @patch(f"{VAULT_MANAGERS_PATH}.generate_ca")
    @patch(f"{VAULT_MANAGERS_PATH}.generate_certificate")
    @patch(f"{VAULT_MANAGERS_PATH}.generate_vault_ca_certificate")
    def test_given_tls_relation_and_ca_secret_exists_but_no_certs_in_workload_when_configure_self_signed_certificates_then_certs_pushed(
        self,
        patch_generate_vault_ca_certificate: MagicMock,
        patch_generate_certificate: MagicMock,
        patch_generate_ca: MagicMock,
    ):
        self_signed_private_key = generate_private_key()
        self_signed_ca_private_key = generate_private_key()
        self_signed_ca_certificate = generate_ca(
            common_name=VAULT_CA_SUBJECT,
            private_key=self_signed_ca_private_key,
            validity=timedelta(days=365),
        )
        self_signed_csr = generate_csr(
            private_key=self_signed_private_key,
            common_name="my.domain",
        )
        self_signed_certificate = generate_certificate(
            csr=self_signed_csr,
            ca=self_signed_ca_certificate,
            ca_private_key=self_signed_ca_private_key,
            validity=timedelta(days=365),
        )
        patch_generate_ca.return_value = self_signed_ca_certificate
        patch_generate_certificate.return_value = self_signed_certificate

        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            ca_certificate_secret = testing.Secret(
                label="self-signed-vault-ca-certificate",
                tracked_content={
                    "privatekey": str(self_signed_ca_private_key),
                    "certificate": str(self_signed_ca_certificate),
                },
                owner="app",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                secrets=[ca_certificate_secret],
                leader=True,
                relations=[peer_relation],
            )
            tls_integration_private_key = generate_private_key()
            tls_integration_ca_private_key = generate_private_key()
            tls_integration_ca_certificate = generate_ca(
                common_name="tls integration ca",
                private_key=tls_integration_ca_private_key,
                validity=timedelta(days=365),
            )
            tls_integration_csr = generate_csr(
                private_key=tls_integration_private_key,
                common_name="my.domain",
            )
            tls_integration_certificate = generate_certificate(
                csr=tls_integration_csr,
                ca=tls_integration_ca_certificate,
                ca_private_key=tls_integration_ca_private_key,
                validity=timedelta(days=365),
            )
            with open(temp_dir + "/ca.pem", "w") as f:
                f.write(str(tls_integration_ca_certificate))
            with open(temp_dir + "/cert.pem", "w") as f:
                f.write(str(tls_integration_certificate))

            self.ctx.run(self.ctx.on.update_status(), state_in)

            patch_generate_vault_ca_certificate.assert_not_called()

            with open(temp_dir + "/ca.pem", "r") as f:
                assert f.read() == str(self_signed_ca_certificate)
            with open(temp_dir + "/cert.pem", "r") as f:
                assert f.read() == str(self_signed_certificate)

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed")
    @patch("vault.vault_client.VaultClient.is_active_or_standby", new=Mock)
    @patch("vault.vault_client.VaultClient.authenticate", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available")
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    @patch(f"{CERTIFICATE_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_ca_cert_exists_when_certificate_transfer_relation_joins_then_ca_cert_is_advertised(
        self, add_certificates: MagicMock, is_api_available: MagicMock, is_sealed: MagicMock
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
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            cert_transfer_relation = testing.Relation(
                endpoint="send-ca-cert",
                interface="certificate_transfer",
                remote_app_name="whatever",
            )
            certs_mount = testing.Mount(
                location="/vault/certs",
                source=temp_dir,
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "certs": certs_mount,
                    "config": config_mount,
                },
            )
            certs_storage = testing.Storage(
                name="certs",
            )
            config_storage = testing.Storage(
                name="config",
            )
            approle_secret = testing.Secret(
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                tracked_content={"role-id": "some role id", "secret-id": "some secret"},
                owner="app",
            )
            ca_certificate_secret = testing.Secret(
                label=CA_CERTIFICATE_JUJU_SECRET_LABEL,
                tracked_content={"privatekey": "some private key", "certificate": "some cert"},
                owner="app",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[certs_storage, config_storage],
                secrets=[approle_secret, ca_certificate_secret],
                leader=True,
                relations=[peer_relation, cert_transfer_relation],
            )

            self.ctx.run(self.ctx.on.relation_joined(cert_transfer_relation), state_in)

            add_certificates.assert_called_once_with(
                certificates=set("some ca"),
                relation_id=cert_transfer_relation.id,
            )

    @patch("vault.vault_client.VaultClient.enable_audit_device", new=Mock)
    @patch("vault.vault_client.VaultClient.is_active", new=Mock)
    @patch("vault.vault_client.VaultClient.is_sealed")
    @patch("vault.vault_client.VaultClient.is_active_or_standby", new=Mock)
    @patch("vault.vault_client.VaultClient.authenticate", new=Mock)
    @patch("vault.vault_client.VaultClient.is_initialized", new=Mock)
    @patch("vault.vault_client.VaultClient.is_api_available")
    @patch("vault.vault_client.VaultClient.is_raft_cluster_healthy", new=Mock)
    @patch(f"{CERTIFICATE_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_ca_cert_is_not_stored_when_certificate_transfer_relation_joins_then_ca_cert_is_not_advertised(
        self, add_certificates: MagicMock, is_api_available: MagicMock, is_sealed: MagicMock
    ):
        is_api_available.return_value = True
        is_sealed.return_value = False
        with tempfile.TemporaryDirectory() as temp_dir:
            peer_relation = testing.PeerRelation(
                endpoint="vault-peers",
                interface="vault-peer",
                local_unit_data={"node_api_address": "http://1.2.3.4"},
            )
            cert_transfer_relation = testing.Relation(
                endpoint="send-ca-cert",
                interface="certificate_transfer",
                remote_app_name="whatever",
            )
            config_mount = testing.Mount(
                location="/vault/config",
                source=temp_dir,
            )
            vault_container = testing.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "config": config_mount,
                },
            )
            config_storage = testing.Storage(
                name="config",
            )
            approle_secret = testing.Secret(
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                tracked_content={"role-id": "some role id", "secret-id": "some secret"},
                owner="app",
            )
            state_in = testing.State(
                containers=[vault_container],
                storages=[config_storage],
                secrets=[approle_secret],
                leader=True,
                relations=[peer_relation, cert_transfer_relation],
            )

            self.ctx.run(self.ctx.on.relation_joined(cert_transfer_relation), state_in)

            add_certificates.assert_not_called()
