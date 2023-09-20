#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for the vault-kv relation.

This library contains the Requires and Provides classes for handling the vault-kv
interface.

## Getting Started
From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.vault_k8s.v0.vault_kv
```

### Requirer charm
The requirer charm is the charm requiring a secret value store. In this example, the requirer charm
is requiring a secret value store.

import secrets

from charms.vault_k8s.v0 import vault_kv
from ops.charm import CharmBase, InstallEvent
from ops import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

class ExampleRequirerCharm(CharmBase):
    _stored = ops.StoredState()
    def __init__(self, *args):
        super().__init__(*args)
        self._stored.set_default(nonce=secrets.token_hex(16))
        self.interface = vault_kv.VaultKvRequires(
            self,
            "vault-kv",
            "my-suffix",
            self._stored.nonce,
        )

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.interface.on.connected, self._on_connected)
        self.framework.observe(self.interface.on.ready, self._on_ready)
        self.framework.observe(self.interface.on.gone_away, self._on_gone_away)
        self.framework.observe(self.on.update_status, self._on_update_status)

    def _on_install(self, event: InstallEvent):
        self.interface.request_credentials()
        self.unit.status = BlockedStatus("Waiting for vault-kv relation")

    def _on_connected(self, event: vault_kv.VaultKvConnectedEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        egress_subnet = self.model.get_binding(relation).network.interfaces[0].subnet
        self.interface.request_credentials(relation, egress_subnet)

    def _on_ready(self, event: vault_kv.VaultKvReadyEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        if relation is None:
            return
        vault_url = self.interface.vault_url(relation)
        ca_certificate = self.interface.ca_certificate(relation)
        mount = self.interface.mount(relation)

        unit_credentials = self.interface.unit_credentials(relation)
        # unit_credentials is a juju secret id
        secret = self.model.get_secret(id=unit_credentials)
        secret_content = secret.get_content(refresh=True)
        role_id = secret_content["role-id"]
        role_secret_id = secret_content["role-secret-id"]

        self._configure(vault_url, ca_certificate, mount, role_id, role_secret_id)

        self.unit.status = ActiveStatus()

    def _on_gone_away(self, event: vault_kv.VaultKvGoneAwayEvent):
        self.unit.status = BlockedStatus("Waiting for vault-kv relation")

    def _configure(
            self,
            vault_url: str,
            ca_certificate: str,
            mount: str,
            role_id: str,
            role_secret_id: str,
        ):
        pass

    def _on_update_status(self, event):
        # Check somewhere that egress subnet has not changed i.e. pod has not been rescheduled
        # Update status might not be the best place
        binding = self.model.get_binding("vault-kv")
        if binding is not None
            egress_subnet = binding.network.interfaces[0].subnet
            self.interface.request_credentials(event.relation, egress_subnet)


if __name__ == "__main__":
    main(ExampleRequirerCharm)

You can integrate both charms by running:

```bash
juju integrate <vault provider charm> <vault requirer charm>
```
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union

import ops

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "to_fill"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class NewVaultKvClientAttachedEvent(ops.EventBase):
    """New vault kv client attached event."""

    def __init__(
        self,
        handle: ops.Handle,
        relation_id: int,
        relation_name: str,
        mount_suffix: str,
    ):
        super().__init__(handle)
        self.relation_id = relation_id
        self.relation_name = relation_name
        self.mount_suffix = mount_suffix

    def snapshot(self) -> dict:
        """Return snapshot data that should be persisted."""
        return {
            "relation_id": self.relation_id,
            "relation_name": self.relation_name,
            "mount_suffix": self.mount_suffix,
        }

    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from a given snapshot."""
        super().restore(snapshot)
        self.relation_id = snapshot["relation_id"]
        self.relation_name = snapshot["relation_name"]
        self.mount_suffix = snapshot["mount_suffix"]


class VaultKvProviderEvents(ops.ObjectEvents):
    """List of events that the Vault Kv provider charm can leverage."""

    new_vault_kv_client_attached = ops.EventSource(NewVaultKvClientAttachedEvent)


class VaultKvProvides(ops.Object):
    """Class to be instanciated by the providing side of the relation."""

    on = VaultKvProviderEvents()

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
    ) -> None:
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_relation_changed,
        )

    def _on_relation_changed(self, event: ops.RelationChangedEvent):
        """Handle client changed relation."""
        if event.app is None:
            logger.debug("No remote application yet")
            return

        mount_suffix = event.relation.data[event.app].get("mount_suffix")

        if mount_suffix is not None:
            self.on.new_vault_kv_client_attached.emit(
                event.relation.id,
                event.relation.name,
                mount_suffix,
            )

    def set_vault_url(self, relation: ops.Relation, vault_url: str):
        """Set the vault_url on the relation."""
        if not self.charm.unit.is_leader():
            return

        relation.data[self.charm.app]["vault_url"] = vault_url

    def set_ca_certificate(self, relation: ops.Relation, ca_certificate: str):
        """Set the ca_certificate on the relation."""
        if not self.charm.unit.is_leader():
            return

        relation.data[self.charm.app]["ca_certificate"] = ca_certificate

    def set_mount(self, relation: ops.Relation, mount: str):
        """Set the mount on the relation."""
        if not self.charm.unit.is_leader():
            return

        relation.data[self.charm.app]["mount"] = mount

    def set_unit_credentials(self, relation: ops.Relation, nonce: str, secret: ops.Secret):
        """Set the unit credentials on the relation."""
        if not self.charm.unit.is_leader():
            return

        credentials = self.get_credentials(relation)
        if secret.id is None:
            logger.debug(
                "Secret id is None, not updating the relation '%s:%d' for nonce %r",
                relation.name,
                relation.id,
                nonce,
            )
            return
        credentials[nonce] = secret.id
        relation.data[self.charm.app]["credentials"] = json.dumps(credentials, sort_keys=True)

    def remove_unit_credentials(self, relation: ops.Relation, nonce: Union[str, List[str]]):
        """Remove nonce(s) from the relation."""
        if not self.charm.unit.is_leader():
            return

        if isinstance(nonce, str):
            nonce = [nonce]

        credentials = self.get_credentials(relation)

        for n in nonce:
            credentials.pop(n, None)

        relation.data[self.charm.app]["credentials"] = json.dumps(credentials, sort_keys=True)

    def get_credentials(self, relation: ops.Relation) -> dict:
        """Get the unit credentials from the relation."""
        return json.loads(relation.data[self.charm.app].get("credentials", "{}"))


class VaultKvConnectedEvent(ops.EventBase):
    """VaultKvConnectedEvent Event."""

    def __init__(
        self,
        handle: ops.Handle,
        relation_id: int,
        relation_name: str,
    ):
        super().__init__(handle)
        self.relation_id = relation_id
        self.relation_name = relation_name

    def snapshot(self) -> dict:
        """Return snapshot data that should be persisted."""
        return {
            "relation_id": self.relation_id,
            "relation_name": self.relation_name,
        }

    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from a given snapshot."""
        super().restore(snapshot)
        self.relation_id = snapshot["relation_id"]
        self.relation_name = snapshot["relation_name"]


class VaultKvReadyEvent(ops.EventBase):
    """VaultKvReadyEvent Event."""

    def __init__(
        self,
        handle: ops.Handle,
        relation_id: int,
        relation_name: str,
        vault_url: str,
        ca_certificate: str,
        mount: str,
        credentials_secret: str,
    ):
        super().__init__(handle)
        self.relation_id = relation_id
        self.relation_name = relation_name
        self.vault_url = vault_url
        self.ca_certificate = ca_certificate
        self.mount = mount
        self.credentials_secret = credentials_secret

    def snapshot(self) -> dict:
        """Return snapshot data that should be persisted."""
        return {
            "relation_id": self.relation_id,
            "relation_name": self.relation_name,
            "vault_url": self.vault_url,
            "ca_certificate": self.ca_certificate,
            "mount": self.mount,
            "credentials_secret": self.credentials_secret,
        }

    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from a given snapshot."""
        super().restore(snapshot)
        self.relation_id = snapshot["relation_id"]
        self.relation_name = snapshot["relation_name"]
        self.vault_url = snapshot["vault_url"]
        self.ca_certificate = snapshot["ca_certificate"]
        self.mount = snapshot["mount"]
        self.credentials_secret = snapshot["credentials_secret"]


class VaultKvGoneAwayEvent(ops.EventBase):
    """VaultKvGoneAwayEvent Event."""

    pass


class VaultKvRequireEvents(ops.ObjectEvents):
    """List of events that the Vault Kv requirer charm can leverage."""

    connected = ops.EventSource(VaultKvConnectedEvent)
    ready = ops.EventSource(VaultKvReadyEvent)
    gone_away = ops.EventSource(VaultKvGoneAwayEvent)


class VaultKvRequires(ops.Object):
    """Class to be instanciated by the requiring side of the relation."""

    on = VaultKvRequireEvents()

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
        mount_suffix: str,
        nonce: str,
    ) -> None:
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.mount_suffix = mount_suffix
        self.nonce = nonce
        self.framework.observe(
            self.charm.on[relation_name].relation_joined,
            self._on_vault_kv_relation_joined,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_vault_kv_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken,
            self._on_vault_kv_relation_broken,
        )

    def _set_unit_nonce(self, relation: ops.Relation, nonce: str):
        """Set the nonce on the relation."""
        relation.data[self.charm.unit]["nonce"] = nonce

    def _set_unit_egress_subnet(self, relation: ops.Relation, egress_subnet: str):
        """Set the egress_subnet on the relation."""
        relation.data[self.charm.unit]["egress_subnet"] = egress_subnet

    def _on_vault_kv_relation_joined(self, event: ops.RelationJoinedEvent):
        """Handle relation joined.

        Set the secret backend in the application databag if we are the leader.
        Always update the egress_subnet in the unit databag.
        """
        if self.charm.unit.is_leader():
            event.relation.data[self.charm.app]["mount_suffix"] = self.mount_suffix
        self._set_unit_nonce(event.relation, self.nonce)
        self.on.connected.emit(
            event.relation.id,
            event.relation.name,
        )

    def _on_vault_kv_relation_changed(self, event: ops.RelationChangedEvent):
        """Handle relation changed."""
        if event.app is None:
            logger.debug("No remote application yet")
            return

        vault_url = self.vault_url(event.relation)
        ca_certificate = self.ca_certificate(event.relation)
        mount = self.mount(event.relation)
        unit_credentials_secret = self.unit_credentials(event.relation)
        if all((vault_url, ca_certificate, mount, unit_credentials_secret)):
            self.on.ready.emit(
                event.relation.id,
                event.relation.name,
                vault_url,
                ca_certificate,
                mount,
                unit_credentials_secret,
            )

    def _on_vault_kv_relation_broken(self, event: ops.RelationBrokenEvent):
        """Handle relation broken."""
        self.on.gone_away.emit()

    def request_credentials(self, relation: ops.Relation, egress_subnet: str) -> None:
        """Request credentials from the vault-kv relation.

        Generated secret ids are tied to the unit egress_subnet, so if the egress_subnet
        changes a new secret id must be generated.

        A change in egress_subnet can happen when the pod is rescheduled to a different
        node by the underlying substrate without a change from Juju.
        """
        self._set_unit_egress_subnet(relation, egress_subnet)
        self._set_unit_nonce(relation, self.nonce)

    def vault_url(self, relation: ops.Relation) -> Optional[str]:
        """Return the vault_url from the relation."""
        if relation.app is None:
            return None
        return relation.data[relation.app].get("vault_url")

    def ca_certificate(self, relation: ops.Relation) -> Optional[str]:
        """Return the ca_certificate from the relation."""
        if relation.app is None:
            return None
        return relation.data[relation.app].get("ca_certificate")

    def mount(self, relation: ops.Relation) -> Optional[str]:
        """Return the mount from the relation."""
        if relation.app is None:
            return None
        return relation.data[relation.app].get("mount")

    def unit_credentials(self, relation: ops.Relation) -> Optional[str]:
        """Return the unit credentials from the relation.

        Unit credentials are stored in the relation data as a Juju secret id.
        """
        if relation.app is None:
            return None
        return json.loads(relation.data[relation.app].get("credentials", "{}")).get(self.nonce)
