#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

import hcl
import scenario
from charms.tls_certificates_interface.v4.tls_certificates import ProviderCertificate
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    Certificate,
    SecretsBackend,
)
from charms.vault_k8s.v0.vault_kv import KVRequest
from ops.pebble import Layer

from tests.unit.certificates import (
    generate_example_provider_certificate,
    generate_example_requirer_csr,
    sign_certificate,
)
from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class MockRelation:
    def __init__(self, id: int):
        self.id = id


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_socket_fqdn.return_value = "myhostname"
            self.mock_autounseal_requires_get_details.return_value = None
            model_name = "whatever"
            vault_raft_mount = scenario.Mount(
                location="/vault/raft",
                src=temp_dir,
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-raft": vault_raft_mount,
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
                model=scenario.Model(name=model_name),
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()

            with open("tests/unit/config.hcl", "r") as f:
                expected_config = f.read()
            actual_content_hcl = hcl.loads(actual_config)
            expected_content_hcl = hcl.loads(expected_config)
            assert actual_content_hcl == expected_content_hcl

    def test_given_leader_when_configure_then_pebble_layer_is_planned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
            )

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            assert state_out.containers[0].layers == {
                "vault": Layer(
                    {
                        "summary": "vault layer",
                        "description": "pebble config layer for vault",
                        "services": {
                            "vault": {
                                "summary": "vault",
                                "startup": "enabled",
                                "override": "replace",
                                "command": "vault server -config=/vault/config/vault.hcl",
                            }
                        },
                    }
                )
            }

    # PKI

    def test_given_certificate_available_when_configure_then_pki_secrets_engine_is_configured(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "get_intermediate_ca.return_value": "",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
            )
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation],
                config={"common_name": "myhostname.com"},
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation.relation_id,
            )
            self.mock_pki_requirer_get_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.enable_secrets_engine.assert_called_once_with(
                SecretsBackend.PKI, "charm-pki"
            )
            self.mock_vault.import_ca_certificate_and_key.assert_called_once_with(
                certificate=str(provider_certificate.certificate),
                private_key=str(private_key),
                mount="charm-pki",
            )
            self.mock_vault.make_latest_pki_issuer_default.assert_called_once_with(
                mount="charm-pki",
            )
            self.mock_vault.create_or_update_pki_charm_role.assert_called_once_with(
                allowed_domains="myhostname.com",
                mount="charm-pki",
                role="charm",
            )

    def test_given_vault_available_when_configure_then_certificate_is_provided(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            pki_relation_requirer = scenario.Relation(
                endpoint="vault-pki",
                interface="tls-certificates",
                remote_app_name="tls-requirer",
            )
            assigned_provider_certificate, assigned_private_key = (
                generate_example_provider_certificate(
                    common_name="myhostname.com",
                    relation_id=pki_relation_provider.relation_id,
                )
            )
            requirer_csr = generate_example_requirer_csr(
                common_name="subdomain.myhostname.com",
                relation_id=pki_relation_requirer.relation_id,
            )

            self.mock_pki_requirer_get_assigned_certificate.return_value = (
                assigned_provider_certificate,
                assigned_private_key,
            )
            self.mock_pki_provider_get_outstanding_certificate_requests.return_value = [
                requirer_csr
            ]
            vault_generated_certificate = sign_certificate(
                ca_certificate=assigned_provider_certificate.certificate,
                ca_private_key=assigned_private_key,
                csr=requirer_csr.certificate_signing_request,
            )
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, pki_relation_requirer],
                config={"common_name": "myhostname.com"},
            )
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "get_intermediate_ca.return_value": "",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "sign_pki_certificate_signing_request.return_value": Certificate(
                        certificate=str(vault_generated_certificate),
                        ca=str(assigned_provider_certificate.certificate),
                        chain=[str(assigned_provider_certificate.certificate)],
                    ),
                },
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.sign_pki_certificate_signing_request.assert_called_once_with(
                mount="charm-pki",
                role="charm",
                csr=str(requirer_csr.certificate_signing_request),
                common_name="subdomain.myhostname.com",
            )
            self.mock_pki_provider_set_relation_certificate.assert_called_once_with(
                provider_certificate=ProviderCertificate(
                    relation_id=pki_relation_requirer.relation_id,
                    certificate=vault_generated_certificate,
                    ca=assigned_provider_certificate.certificate,
                    chain=[assigned_provider_certificate.certificate],
                    certificate_signing_request=requirer_csr.certificate_signing_request,
                ),
            )

    # Test Auto unseal

    def test_given_autounseal_details_available_when_configure_then_transit_stanza_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_name = "my key"
            approle_id = "my approle id"
            approle_secret_id = "my approle secret id"
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "get_intermediate_ca.return_value": "",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "create_autounseal_credentials.return_value": (
                        key_name,
                        approle_id,
                        approle_secret_id,
                    ),
                },
            )
            self.mock_tls.configure_mock(
                **{
                    "pull_tls_file_from_workload.return_value": "my ca",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
                "1.2.3.4", "charm-autounseal", "key name", "role id", "secret id", "ca cert"
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            vault_autounseal_relation = scenario.Relation(
                endpoint="vault-autounseal-provides",
                interface="vault-autounseal",
                remote_app_name="vault-autounseal-requirer",
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation_provider.relation_id,
            )
            self.mock_get_binding.return_value = MockBinding(
                bind_address="myhostname",
                ingress_address="myhostname",
            )
            self.mock_pki_requirer_get_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )
            relation = MockRelation(id=vault_autounseal_relation.relation_id)
            self.mock_autounseal_provides_get_outstanding_requests.return_value = [relation]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, vault_autounseal_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()
            actual_config_hcl = hcl.loads(actual_config)
            assert actual_config_hcl["seal"]["transit"]["address"] == "1.2.3.4"
            assert actual_config_hcl["seal"]["transit"]["mount_path"] == "charm-autounseal"
            assert actual_config_hcl["seal"]["transit"]["token"] == "some token"
            assert actual_config_hcl["seal"]["transit"]["key_name"] == "key name"
            self.mock_vault.authenticate.assert_called_with(AppRole("role id", "secret id"))
            self.mock_tls.push_autounseal_ca_cert.assert_called_with("ca cert")

    def test_given_outstanding_autounseal_requests_when_configure_then_credentials_are_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            key_name = "my key"
            approle_id = "my approle id"
            approle_secret_id = "my approle secret id"
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "get_intermediate_ca.return_value": "",
                    "create_autounseal_credentials.return_value": (
                        key_name,
                        approle_id,
                        approle_secret_id,
                    ),
                },
            )
            self.mock_tls.configure_mock(
                **{
                    "pull_tls_file_from_workload.return_value": "my ca",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            vault_autounseal_relation = scenario.Relation(
                endpoint="vault-autounseal-provides",
                interface="vault-autounseal",
                remote_app_name="vault-autounseal-requirer",
            )
            provider_certificate, private_key = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation_provider.relation_id,
            )
            self.mock_get_binding.return_value = MockBinding(
                bind_address="myhostname",
                ingress_address="myhostname",
            )
            self.mock_pki_requirer_get_assigned_certificate.return_value = (
                provider_certificate,
                private_key,
            )
            relation = MockRelation(id=vault_autounseal_relation.relation_id)
            self.mock_autounseal_provides_get_outstanding_requests.return_value = [relation]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, vault_autounseal_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_autounseal_provides_set_data.assert_called_with(
                relation,
                "https://myhostname:8200",
                "charm-autounseal",
                key_name,
                approle_id,
                approle_secret_id,
                "my ca",
            )

    def test_given_outstanding_kv_request_when_configure_then_kv_relation_data_is_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "generate_role_secret_id.return_value": "kv role secret id",
                    "configure_approle.return_value": "kv role id",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            kv_relation = scenario.Relation(
                endpoint="vault-kv",
                interface="vault-kv",
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation, kv_relation],
                secrets=[approle_secret],
            )
            self.mock_kv_provides_get_outstanding_kv_requests.return_value = [
                KVRequest(
                    relation_id=kv_relation.relation_id,
                    app_name="vault-kv-remote",
                    unit_name="vault-kv-remote/0",
                    mount_suffix="suffix",
                    egress_subnets=["2.2.2.0/24"],
                    nonce="123123",
                )
            ]
            self.mock_kv_provides_get_credentials.return_value = {}

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.enable_secrets_engine.assert_called_once_with(
                SecretsBackend.KV_V2, "charm-vault-kv-remote-suffix"
            )
            self.mock_kv_provides_set_ca_certificate.assert_called()
            self.mock_kv_provides_set_egress_subnets.assert_called()
            self.mock_kv_provides_set_vault_url.assert_called()
            assert state_out.secrets[1].label == "kv-creds-vault-kv-remote-0"
            assert state_out.secrets[1].contents == {
                0: {"role-id": "kv role id", "role-secret-id": "kv role secret id"}
            }

    def test_given_related_kv_client_unit_egress_is_updated_when_configure_then_secret_content_is_updated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            nonce = "123123"
            self.mock_vault.configure_mock(
                **{
                    "token": "some token",
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "generate_role_secret_id.return_value": "new kv role secret id",
                    "configure_approle.return_value": "kv role id",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None

            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            kv_relation = scenario.Relation(
                endpoint="vault-kv",
                interface="vault-kv",
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            kv_secret = scenario.Secret(
                id="1",
                label="kv-creds-vault-kv-remote-0",
                contents={
                    0: {"role-id": "kv role id", "role-secret-id": "initial kv role secret id"}
                },
                owner="app",
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation, kv_relation],
                secrets=[approle_secret, kv_secret],
            )
            self.mock_kv_provides_get_outstanding_kv_requests.return_value = [
                KVRequest(
                    relation_id=kv_relation.relation_id,
                    app_name="vault-kv-remote",
                    unit_name="vault-kv-remote/0",
                    mount_suffix="suffix",
                    egress_subnets=["2.2.2.0/24"],
                    nonce=nonce,
                )
            ]
            self.mock_kv_provides_get_credentials.return_value = {nonce: kv_secret.id}

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            assert state_out.secrets[1].label == "kv-creds-vault-kv-remote-0"
            assert state_out.secrets[1].contents == {
                0: {"role-id": "kv role id", "role-secret-id": "initial kv role secret id"},
                1: {"role-id": "kv role id", "role-secret-id": "new kv role secret id"},
            }
