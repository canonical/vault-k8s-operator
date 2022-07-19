#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm for Vault running on Kubernetes.

For more information on Vault, please visit https://www.vaultproject.io/.
"""

import json
import logging

from charms.observability_libs.v1.kubernetes_service_patch import (
    KubernetesServicePatch,
    ServicePort,
)
from charms.tls_certificates_interface.v0.tls_certificates import (
    Cert,
    TLSCertificatesProvides,
)
from ops.charm import ActionEvent, CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from ops.pebble import Layer

from vault import Vault

logger = logging.getLogger(__name__)

VAULT_STORAGE_PATH = "/srv"


class VaultCharm(CharmBase):
    """Main class for to handle Juju events."""

    VAULT_PORT = 8200
    VAULT_CLUSTER_PORT = 8201

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self._stored.set_default(role_id="", secret_id="")  # type: ignore[union-attr, arg-type]
        self.tls_certificates = TLSCertificatesProvides(self, "certificates")
        self.vault = Vault(
            url=f"http://localhost:{self.VAULT_PORT}",
            role_id=self._stored.role_id,  # type: ignore[union-attr, arg-type]
            secret_id=self._stored.secret_id,  # type: ignore[union-attr, arg-type]
        )
        self._service_name = self._container_name = "vault"
        self._container = self.unit.get_container(self._container_name)
        self.framework.observe(
            self.tls_certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(self.on.vault_pebble_ready, self._on_config_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.authorise_charm_action, self._on_authorise_charm_action)
        self.framework.observe(
            self.on.generate_certificate_action, self._on_generate_certificate_action
        )
        self.service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="vault", port=8200)],
            service_type="LoadBalancer",
        )

    def _on_certificate_request(self, event) -> None:
        """Handler triggered whenever there is a request made from a requirer charm to vault.

        Args:
            event: Juju event

        Returns:
            None
        """
        certificate = self.vault.issue_certificate(
            cert_type=event.cert_type, common_name=event.common_name, sans=event.sans
        )
        self.tls_certificates.set_relation_certificate(
            certificate=Cert(
                cert=certificate["certificate"],
                key=certificate["private_key"],
                ca=certificate["issuing_ca"],
                common_name=event.common_name,
            ),
            relation_id=event.relation_id,
        )

    def _on_config_changed(self, event) -> None:
        """Handler triggerred whenever there is a config-changed event.

        Args:
            event: Juju event

        Returns:
            None
        """
        if not self._container.can_connect():
            event.defer()
            return
        plan = self._container.get_plan()
        layer = self._vault_layer
        if plan.services != layer.services:
            self.unit.status = MaintenanceStatus(
                f"Configuring pebble layer for {self._service_name}"
            )
            self._container.add_layer(self._container_name, layer, combine=True)
            logger.info("Added updated layer 'vault' to Pebble plan")
            self._container.replan()
            logger.info("Replanned pebble Layer")
        self._patch_storage_ownership()
        self.unit.status = BlockedStatus("Waiting for `authorise-charm` action to be triggered.")

    @property
    def _bind_address(self) -> str:
        """Fetches bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        peer_relation = self.model.get_relation("peers")
        return str(
            self.model.get_binding(peer_relation).network.bind_address  # type: ignore[arg-type, union-attr]  # noqa: E501
        )

    @property
    def _vault_layer(self) -> Layer:
        """Returns pebble layer to start Vault.

        Vault config options:
            backend: Configures the storage backend where Vault data is stored.
            listener: Configures how Vault is listening for API requests.
            default_lease_ttl: Specifies the default lease duration for Vault's tokens and secrets.
            max_lease_ttl: Specifies the maximum possible lease duration for Vault's tokens and
                secrets.
            disable_mlock: mlock() ensures memory from a process on a Linux system isn't swapped
                (written) to disk. Enabling mlock would require the operator to add IPC_LOCK
                capabilities to the vault pod which isn't even necessary since Kubernetes, by
                default, doesn't enable swap.
            cluster_addr: Specifies the address to advertise to other Vault servers in the cluster
                for request forwarding.
            api_addr: Specifies the address (full URL) to advertise to other Vault servers in the
                cluster for client redirection

        Returns:
            Layer: Pebble Layer
        """
        backends = {"file": {"path": VAULT_STORAGE_PATH}}
        vault_config = {
            "backend": backends,
            "listener": {"tcp": {"tls_disable": True, "address": f"[::]:{self.VAULT_PORT}"}},
            "default_lease_ttl": self.model.config["default_lease_ttl"],
            "max_lease_ttl": self.model.config["max_lease_ttl"],
            "disable_mlock": True,
            "cluster_addr": f"http://{self._bind_address}:{self.VAULT_CLUSTER_PORT}",
            "api_addr": f"http://{self._bind_address}:{self.VAULT_PORT}",
        }

        return Layer(
            {
                "summary": "vault layer",
                "description": "pebble config layer for vault",
                "services": {
                    "vault": {
                        "override": "replace",
                        "summary": "vault",
                        "command": "/usr/local/bin/docker-entrypoint.sh server",
                        "startup": "enabled",
                        "environment": {
                            "VAULT_LOCAL_CONFIG": json.dumps(vault_config),
                            "VAULT_API_ADDR": f"http://[::]:{self.VAULT_PORT}",
                        },
                    }
                },
            }
        )

    def _patch_storage_ownership(self) -> None:
        """Fix up storage permissions (broken on AWS and GCP otherwise)'.

        Returns:
            None
        """
        command = ["chown", "100:1000", VAULT_STORAGE_PATH]
        self._container.exec(command=command)

    def _on_authorise_charm_action(self, event: ActionEvent) -> None:
        """Create a role allowing the charm to perform certain vault actions.

        Args:
            event: Juju event

        Returns:
            None
        """
        if self.unit.is_leader():
            self.vault.set_token(token=event.params["token"])
            if not self.vault.is_ready:
                self.vault.enable_secrets_engine()
                self.vault.generate_root_certificate()
                self.vault.write_roles()
                self.vault.enable_approle_auth()
                self.vault.create_local_charm_policy()
                self.vault.create_local_charm_access_approle()
            role_id, secret_id = self.vault.get_approle_auth_data()
            self._stored.role_id = role_id  # type: ignore[union-attr]
            self._stored.secret_id = secret_id  # type: ignore[union-attr]
            self.unit.status = ActiveStatus()

    def _on_generate_certificate_action(self, event: ActionEvent) -> None:
        """Generates TLS Certificate.

        Args:
            event: Juju event.

        Returns:
            None
        """
        certificate = self.vault.issue_certificate(
            cert_type="server", common_name=event.params["common_name"], sans=event.params["sans"]
        )
        event.set_results(
            {
                "certificate": certificate["certificate"],
                "private-key": certificate["private_key"],
                "ca": certificate["issuing_ca"],
            }
        )


if __name__ == "__main__":
    main(VaultCharm)
