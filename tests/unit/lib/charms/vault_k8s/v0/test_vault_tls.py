#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from signal import SIGHUP
from typing import List
from unittest.mock import Mock, patch

from charms.vault_k8s.v0.vault_tls import CA_CERTIFICATE_JUJU_SECRET_LABEL
from ops import testing
from ops.model import WaitingStatus

from charm import VAULT_INITIALIZATION_SECRET_LABEL, VaultCharm

TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v2.tls_certificates"
EXAMPLE_CA = "-----BEGIN CERTIFICATE-----\nMIIDTzCCAjegAwIBAgIUC+ohQChfeaZDz6MnMTXnJ6gkJN4wDQYJKoZIhvcNAQEL\nBQAwLDELMAkGA1UEBhMCVVMxHTAbBgNVBAMMFFZhdWx0IHNlbGYgc2lnbmVkIENB\nMCAXDTI0MDExOTA5NTcyMFoYDzIwNzQwMTA2MDk1NzIwWjAsMQswCQYDVQQGEwJV\nUzEdMBsGA1UEAwwUVmF1bHQgc2VsZiBzaWduZWQgQ0EwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQDHdlv5i5rbQjm9qVhGpHFhAincmuocP0OiJm/QANT/\nFqJKnwogMTkb69jn73nXQCqmiNT/r06tTux6nHCjdzjYu/SzfYIUTzrYFbiXJc8e\n9YfyO1bykiZ5W4QoZvuj2QqWp+n2fuXEoBKSbYzKnlwWSk0uhwdYkJ/yZU5zWnOO\nFSsFASGvgHMpo5NZ+qB9/r+jqwofpJbB7VsRlwVukZdqqblE2c4dL2KT/nv5DNko\nqTxQOymG+c/yiGkU5+UUWGyS34u51E9+iAhtome+Tl54PptCnXCyKqzjOz5Kj8F0\noGmsWEk0L1oSog9yNJaVN2pzZDLnHBvo6oSp+tPDX+exAgMBAAGjZzBlMB8GA1Ud\nDgQYBBYEFLAfjFTRAA+o3iE6xPyo3BPPg9LMMCEGA1UdIwQaMBiAFgQUsB+MVNEA\nD6jeITrE/KjcE8+D0swwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8w\nDQYJKoZIhvcNAQELBQADggEBAJOkUoMxS3arCbtXXr+3O35FJThy2V643zyAQAoF\n/ndgZPMhPbx8WfAltkylUgj4LXcZw98BhYe49YfGvlQwu8oh/8ENavNzZVNdJcMO\nCliN1ZjV9goRXAl/sUesswMojGJTQaDuWfOXn4NCA6B72NDKz+vPVj1DLe/bDOQ2\noi5KbaJsRbkfW7dj61iwXtOW6PYT6gDeQLJRvLGU2v0ORXet7yu1aVkdPIsfhl6G\nfC+Tdubb1GTRF5JgzXxTMFgaKOmy5u9KHK36TLUX034YfYzksMya7y7SeRT18Uxd\npQSmmO0rHitHDAi9O1bsZCBmbyJhxyE3mGdYKhk1pouedUg=\n-----END CERTIFICATE-----"
EXAMPLE_CA_PK = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx3Zb+Yua20I5valYRqRxYQIp3JrqHD9DoiZv0ADU/xaiSp8K\nIDE5G+vY5+9510AqpojU/69OrU7sepxwo3c42Lv0s32CFE862BW4lyXPHvWH8jtW\n8pImeVuEKGb7o9kKlqfp9n7lxKASkm2Myp5cFkpNLocHWJCf8mVOc1pzjhUrBQEh\nr4BzKaOTWfqgff6/o6sKH6SWwe1bEZcFbpGXaqm5RNnOHS9ik/57+QzZKKk8UDsp\nhvnP8ohpFOflFFhskt+LudRPfogIbaJnvk5eeD6bQp1wsiqs4zs+So/BdKBprFhJ\nNC9aEqIPcjSWlTdqc2Qy5xwb6OqEqfrTw1/nsQIDAQABAoIBAAddQQNopRyynZZ5\nZHn546RqQ7NnwNGu1ZzCAIopzbNmrt1EcUeY/vvJ7GXme0Ai7VrdXcfcPXJmoefb\nqMj67jgKUHw5W7kg57zx/bEO7fkS+vmgOT3sKXbSQIHhXinBf1jqoC0VUv8Rzehm\nxQuiEdJSMfalePRLJVdPaDhtaYDLCe4+8vzASi/K5XBN8poj2n8p1XoJghUTG5Hj\n6SN08XvOvM3/KfKyS1pa7TwkU4LESOcrhbXjpjFtJwj94UnpCxx9X+pxx8nR8Yzb\nTbNMgEpIRVYUqz2Z+2YjaSYpMeg4p8FqWnmMAzfLbvUQjpfh2p9DBeF/du33QWd9\nfgtSx5UCgYEA4mrg51s1I6mEp1yas19piW9GPxBYsZ2mjPqzBCqGApWyZHZ6EBb1\npWWlNv6hnszMgoY9RnPaL6nHYNpbqnkPH8MmU46T95bxbtVxfaH/+6J1f+bdr50v\n2+8KZ1iyJBlt7YWa4/foL9QiacKjKNfDL4fGonP54s44MJlNrcGUafMCgYEA4YXl\nRdKW9sLWG2/zPpx4uDIH+XLtFf6pjcNvMvPpM+kUd5tqyVwS8MchEAkr5AQ2Dj1W\nxXpPi28EV6tEyNLUz/JW0WvbR7Bjosjx550LCP+xhMSqoX1haBf4oSxfLUUzr70j\n5EazWjogjz0k6hQplofZQWXEMUPMPtOI+p0FjMsCgYEAmidCcMI8b8detcPq3+06\nIYRNQ2qRuHwphRq6/z8kdmYNSzEO8h1vqeiGj+bVixTMuKFE3s7J4mGpiVuhxXMe\nxPVNBt6wB4YRYvCXkH3Xly+I6Ef67zIJ/6fEYZCV2NYnbevlBQkoYEgCFhealpgw\nIBBFQR3NKIpW31/A72g479kCgYApWxZqMW4BnkUJDwR6LNNuY65Wrh6P8/0/w+D2\nZQgUvt9D97ojZsEKalnDyQrFa4hGIDVzTTSdCySutveMJC1mXLhS+wZhJRWAWn0R\nzhih89Gn2TC5IHbmUc8EL1Dcyl3qEjMsv1JQb2xdGAdW7Y+azRqoBXNu3VHtC3mJ\nC5Zi9QKBgA+SgYgHqkIcEpsZI+zsCCbqnBHlMIZI8uRGHx93Hc1kB/DjhEN7E+ek\nDzqXBlG4cfS7YB4eH1lG9S2y8AcpvRV6u+ggwhkLSX9OoeaevACWsLAC/Olu4jd8\nqtLungNLBJj5AcHycaiGOBzgLTFBZ7J4h4lAk145PnagniETf/gq\n-----END RSA PRIVATE KEY-----"""
EXAMPLE_PK = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAyBE1PlC4FZKAqlRPzkb8/ARpcNhOaDTE8X3Ypy3q+yFV56F7\nyUNOLG5Z0afBdb+eCQI+TabjtSrzKBZYTrjNzQel9g+mUEI+Rn8JyiGiTQ6s1218\nTYlZCenzXj0v9uqu2kyUNEfZBn3/oiugyAX2+6Z52jjZy1/R3mWMt8dBnZnHZiOI\nqXSU8q76GS8j+GiBq3c65MN2A79yl9cKmYRfQLiqwQw6fB7sr0lg4sX6xbQgEApG\nrKRKLBqUeP2QiBZh0fwUk73fXBMgDqcZTrGBTwn46XxqSoaWJNAdGg3bDORfBevn\nRHpg44G1wOlT6xbPkyKDifn1iNR9yL4Egp3OywIDAQABAoIBABG69K0BGk9PHHf7\n4Na3E9SBz5ZglRJHGu0L6hdmylxXJ/XPKdk8TcFCRlN+Onbk9Gx39m2LTMLRe5sh\n39GaLyLsepjD6klSlZJJz+RJ9sg9dLPi0BFPCsUGJrtDUOzg/335K2k2tNUOdYk5\ntJYFcU38AvCD+Uk8xKyg80eWMQp2Xj0ZI9NrbDNvjnsPf92zBOB73nlHUTOFnfi/\ny3LJsotWmSBorn7gpmkGK7W5qyzihs6IHPvUitLfDessCHf7E7SyRu4E/ax2OvIR\nAEFw/ZQeTGJQYYGDULOXEcoeUlNyZXDXEVugi/KbFrxHbKru4EFKLHFuLMswHMse\nbwtg/4ECgYEA7UU//6tPb6QCbqiC0Tw93hoaKln8lgUMJCWbEeLhVFEjzn5sMEmg\nsga7qxPNxmwLfp8/LK2oDhsWMhII9+ZKjoO0nnl81CZCRtG4U9p7x/38GOFUGfAT\nO6jGoLCka/3qG8spsjjV8e6vnBpnjyq1qm8M3Mz8OVj9rdEzzf6A1ycCgYEA19wn\n5vDHXcbANO7/w7Iqhn+zJi1uQj/8lb80B2jVlaUhAVQtIowYcT2CN8Cgtzwj4kaG\n5Dlz1MaIOnVTpHGvGdbUs3HiBuovBgHfJ1+0AQZ7Kg3xIyKGTBNR41LW5t7QQxY9\nhrvd7cJwXbu+usY3v5R2Xkr6/hDx9vcLhy97sb0CgYAugfpvdPbXHUDUy/cIaFSA\nKoGid40JIugkVbK1qNEeI+Fu4lz2ghgbjTJP8EvPbvI52aEacteUHD8XhW14mg1X\nLf3DanDLbMxk8Uq+NP86TlCR1+kSRHqgoQ5+BOHVwSmYVRRROM7G41BMuug9qdN+\nGtJcnVl7LDRdU7ph0FcU1QKBgDKcdeaZ8cS1Av/mQaWasonSiyiaYk26PvjFWeea\n1uk9TF3JZMPC4UA70bpMueH8gdVd/+am6derrOk39SKLXSjLzBc+zmYcpmXcLnxG\n3ieXY21a030PbTmNFhgcpjJ/b4krP8XFaqWCf2Ia0P9t1khfANne7rZ/NpxXFCbg\nJTppAoGABNExOrNs60uhgc7kxc2N3ZCQY4c9F5nf8IkKKSHFF3rFrNIzV7eu0KUo\nkYgXPvh6FAbAuID4OlRFzMkmwt1cPc4eDMbHYnCOKHNtF2L4ogiiMAuFVL3ZBT78\nvj7/gYptiwR7oisVfFPhEx+HXMt96O0wxEHAjs/AmznN/mEfWyU=\n-----END RSA PRIVATE KEY-----\n"


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


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

    def get_valid_s3_params(self):
        """Returns valid S3 parameters for mocking."""
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

    def _set_initialization_secret(
        self,
        root_token: str,
        unseal_keys: List[str],
    ) -> None:
        """Set the initialization secret in the peer relation."""
        content = {
            "roottoken": root_token,
            "unsealkeys": json.dumps(unseal_keys),
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=VAULT_INITIALIZATION_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)

    def _set_ca_certificate_secret(
        self,
        private_key: str,
        certificate: str,
    ) -> None:
        """Set the certificate secret in the peer relation."""
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

    def _set_other_node_api_address_in_peer_relation(
        self,
        relation_id: int,
        unit_name: str,
    ):
        """Set the other node api address in the peer relation."""
        key_values = {"node_api_address": "http://5.2.1.9:8200"}
        self.harness.update_relation_data(
            app_or_unit=unit_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_tls_access_certificate_relation(self):
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(
            relation_name="tls-certificates-access", remote_app="some-tls-provider"
        )

    @patch("ops.model.Model.get_binding")
    def test_given_not_leader_and_ca_not_set_when_configure_then_status_is_waiting(
        self, patch_get_binding
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.app_name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for CA certificate to be set."),
        )

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.audit_device_enabled", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.unseal", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Model.get_binding")
    def test_given_unit_is_leader_and_ca_certificate_not_generated_when_configure_then_ca_certificate_is_generated(
        self,
        patch_get_binding,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_initialization_secret(
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )

        self.harness.charm.on.config_changed.emit()

        secret = self.harness.model.get_secret(
            label=CA_CERTIFICATE_JUJU_SECRET_LABEL
        ).get_content()
        assert secret["privatekey"].startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert secret["certificate"].startswith("-----BEGIN CERTIFICATE-----")

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.audit_device_enabled", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.unseal", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Model.get_binding")
    def test_given_ca_certificate_not_pushed_to_workload_when_configure_then_ca_certificate_pushed(
        self, patch_get_binding, patch_exists
    ):
        self.harness.set_leader(is_leader=True)
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_exists.return_value = False
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate=EXAMPLE_CA,
            private_key=EXAMPLE_CA_PK,
        )
        self._set_initialization_secret(
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual((root / "vault/certs/ca.pem").read_text(), EXAMPLE_CA)

    @patch("charms.vault_k8s.v0.vault_client.Vault.enable_audit_device", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_active", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.audit_device_enabled", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.unseal", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_sealed", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_initialized", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_api_available", new=Mock)
    @patch("charms.vault_k8s.v0.vault_client.Vault.is_raft_cluster_healthy", new=Mock)
    @patch("socket.getfqdn")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Model.get_binding")
    def test_given_unit_certificate_not_stored_when_configure_then_unit_certificate_is_generated(
        self,
        patch_get_binding,
        patch_exists,
        patch_socket_getfqdn,
    ):
        self.harness.set_leader(is_leader=True)
        fqdn = "banana"
        patch_socket_getfqdn.return_value = fqdn
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patch_exists.return_value = False
        ingress_address = "10.1.0.1"
        bind_address = "1.2.1.2"
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate=EXAMPLE_CA,
            private_key=EXAMPLE_CA_PK,
        )
        self._set_initialization_secret(
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.return_value = MockBinding(
            bind_address=bind_address, ingress_address=ingress_address
        )

        self.harness.charm.on.config_changed.emit()

        assert (
            (root / "vault/certs/cert.pem").read_text().startswith("-----BEGIN CERTIFICATE-----")
        )

    def test_given_certificate_access_relation_when_relation_joined_then_new_request_is_created(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        (root / "vault/certs/ca.pem").write_text(EXAMPLE_CA)
        (root / "vault/certs/key.pem").write_text(EXAMPLE_PK)
        (root / "vault/certs/cert.pem").write_text("old cert")

        self._set_peer_relation()
        self._set_tls_access_certificate_relation()
        self.harness.charm.tls.configure_certificates("1.1.1.1")

        assert (root / "vault/certs/csr.pem").exists()

    def test_given_certificate_access_relation_when_cert_available_then_new_cert_saved(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        (root / "vault/certs/key.pem").write_text(EXAMPLE_PK)
        (root / "vault/certs/csr.pem").write_text("some csr")

        self._set_peer_relation()
        rel_id = self._set_tls_access_certificate_relation()

        requirer_databag = [{"certificate_signing_request": "some csr", "ca": False}]

        provider_databag = [
            {
                "ca": "some ca",
                "chain": ["new cert"],
                "certificate": "new cert",
                "certificate_signing_request": "some csr",
            }
        ]

        self.harness.update_relation_data(
            rel_id, "some-tls-provider", {"certificates": json.dumps(provider_databag)}
        )
        self.harness.update_relation_data(
            rel_id,
            self.harness.charm.unit.name,
            {"certificate_signing_requests": json.dumps(requirer_databag)},
        )

        self.harness.charm._container.send_signal = Mock()  # type: ignore [method-assign]
        self.harness.charm.tls.configure_certificates("1.1.1.1")

        self.harness.charm._container.send_signal.assert_called_with(
            signal=SIGHUP, process=self.container_name
        )
        assert (root / "vault/certs/cert.pem").exists()
        assert (root / "vault/certs/ca.pem").exists()

    def test_given_certificate_access_relation_when_wrong_cert_available_then_saved_cert_not_changed(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        (root / "vault/certs/key.pem").write_text(EXAMPLE_PK)
        (root / "vault/certs/ca.pem").write_text(EXAMPLE_CA)
        (root / "vault/certs/csr.pem").write_text("different csr")
        (root / "vault/certs/cert.pem").write_text("different cert")

        self._set_peer_relation()
        rel_id = self._set_tls_access_certificate_relation()

        provider_databag = [
            {
                "ca": "some ca",
                "chain": ["new cert"],
                "certificate": "new cert",
                "certificate_signing_request": "some csr",
            }
        ]

        self.harness.update_relation_data(
            rel_id, "some-tls-provider", {"certificates": json.dumps(provider_databag)}
        )

        self.harness.charm.tls.configure_certificates("1.1.1.1")
        assert (root / "vault/certs/cert.pem").read_text().startswith("different cert")

    @patch("ops.model.Model.get_binding")
    def test_given_certificate_access_relation_when_relation_left_then_previous_state_restored(
        self, patch_get_binding
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        (root / "vault/certs/csr.pem").write_text("first csr")
        (root / "vault/certs/cert.pem").write_text("first cert")
        (root / "vault/certs/ca.pem").write_text("first ca")
        (root / "vault/certs/key.pem").write_text(EXAMPLE_PK)

        self._set_ca_certificate_secret(
            certificate=EXAMPLE_CA,
            private_key=EXAMPLE_CA_PK,
        )
        self._set_initialization_secret(
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )

        self.harness.charm._container.send_signal = Mock()  # type: ignore [method-assign]
        self.harness.charm.tls._on_tls_certificates_access_relation_broken(event=Mock())
        self.harness.charm._container.send_signal.assert_called_with(
            signal=SIGHUP, process=self.container_name
        )
        assert not (root / "vault/certs/csr.pem").exists()
        assert (root / "vault/certs/cert.pem").read_text().startswith("-----BEGIN CERTIFICATE")
        assert (root / "vault/certs/key.pem").read_text().startswith("-----BEGIN RSA PRIVATE KEY")
        assert (root / "vault/certs/ca.pem").read_text() == EXAMPLE_CA

    def test_given_ca_cert_exists_when_certificate_transfer_relation_joins_then_ca_cert_is_advertised(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text(EXAMPLE_CA)
        self.harness.set_can_connect(container=self.container_name, val=True)

        app = "traefik"
        certificate_transfer_rel_id = self.harness.add_relation(
            relation_name="send-ca-cert", remote_app=app
        )

        self.harness.add_relation_unit(
            relation_id=certificate_transfer_rel_id, remote_unit_name=f"{app}/0"
        )

        self.harness.charm.tls.send_ca_cert()

        data = self.harness.get_relation_data(certificate_transfer_rel_id, self.harness.charm.unit)
        ca_from_rel_data = data["ca"]
        self.assertEqual(EXAMPLE_CA, ca_from_rel_data)

    def test_given_ca_cert_is_not_stored_when_certificate_transfer_relation_joins_then_ca_cert_is_not_advertised(
        self,
    ):
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        app = "traefik"
        certificate_transfer_rel_id = self.harness.add_relation(
            relation_name="send-ca-cert", remote_app=app
        )

        self.harness.add_relation_unit(
            relation_id=certificate_transfer_rel_id, remote_unit_name=f"{app}/0"
        )

        relation_data = self.harness.get_relation_data(
            certificate_transfer_rel_id, self.harness.charm.unit
        )

        self.assertNotIn("ca", relation_data)
