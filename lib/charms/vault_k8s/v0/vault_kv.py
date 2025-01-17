#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# Licensed under the Apache2.0. See LICENSE file in charm source for details.

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

```python
import secrets

from charms.vault_k8s.v0 import vault_kv
from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

NONCE_SECRET_LABEL = "nonce"


class ExampleRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.interface = vault_kv.VaultKvRequires(
            self,
            "vault-kv",
            "my-suffix",
        )

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.interface.on.connected, self._on_connected)
        self.framework.observe(self.interface.on.ready, self._on_ready)
        self.framework.observe(self.interface.on.gone_away, self._on_gone_away)
        self.framework.observe(self.on.update_status, self._on_update_status)

    def _on_install(self, event: InstallEvent):
        self.unit.add_secret(
            {"nonce": secrets.token_hex(16)},
            label=NONCE_SECRET_LABEL,
            description="Nonce for vault-kv relation",
        )
        self.unit.status = BlockedStatus("Waiting for vault-kv relation")

    def _on_connected(self, event: vault_kv.VaultKvConnectedEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        egress_subnets = [str(subnet) for subnet in self.model.get_binding(relation).network.egress_subnets][0].subnet]
        egress_subnets.append(str(self.model.get_binding(relation).network.interfaces[0].subnet))
        self.interface.request_credentials(relation, egress_subnets, self.get_nonce())

    def _on_ready(self, event: vault_kv.VaultKvReadyEvent):
        relation = self.model.get_relation(event.relation_name, event.relation_id)
        if relation is None:
            return
        vault_url = self.interface.get_vault_url(relation)
        ca_certificate = self.interface.get_ca_certificate(relation)
        mount = self.interface.get_mount(relation)

        unit_credentials = self.interface.get_unit_credentials(relation)
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
        if binding is not None:
            egress_subnets = [str(subnet) for subnet in self.model.get_binding(relation).network.egress_subnets][0].subnet]
            egress_subnets.append(str(self.model.get_binding(relation).network.interfaces[0].subnet))
            relation = self.model.get_relation(relation_name="vault-kv")
            self.interface.request_credentials(relation, egress_subnets, self.get_nonce())

    def get_nonce(self):
        secret = self.model.get_secret(label=NONCE_SECRET_LABEL)
        nonce = secret.get_content(refresh=True)["nonce"]
        return nonce


if __name__ == "__main__":
    main(ExampleRequirerCharm)
```

You can integrate both charms by running:

```bash
juju integrate <vault provider charm> <vault requirer charm>
```
"""

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Dict, List, MutableMapping

import ops
from charms.vault_k8s.v0.juju_facade import (
    JujuFacade,
    NoSuchRelationError,
    NotLeaderError,
)
from interface_tester.schema_base import DataBagSchema  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, Json, ValidationError

# The unique Charmhub library identifier, never change it
LIBID = "591d6d2fb6a54853b4bb53ef16ef603a"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 15

PYDEPS = ["pydantic", "pytest-interface-tester"]


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_kv"

    def process(self, msg: str, kwargs: MutableMapping) -> tuple[str, MutableMapping]:
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})


class VaultKvProviderSchema(BaseModel):
    """Provider side of the vault-kv interface."""

    vault_url: str = Field(description="The URL of the Vault server to connect to.")
    mount: str = Field(
        description=(
            "The KV mount available for the requirer application, "
            "respecting the pattern 'charm-<requirer app>-<user provided suffix>'."
        )
    )
    ca_certificate: str = Field(
        description="The CA certificate to use when validating the Vault server's certificate."
    )
    credentials: Json[Mapping[str, str]] = Field(
        description=(
            "Mapping of unit name and credentials for that unit."
            " Credentials are a juju secret containing a 'role-id' and a 'role-secret-id'."
        )
    )


class AppVaultKvRequirerSchema(BaseModel):
    """App schema of the requirer side of the vault-kv interface."""

    mount_suffix: str = Field(
        description="Suffix to append to the mount name to get the KV mount."
    )


class UnitVaultKvRequirerSchema(BaseModel):
    """Unit schema of the requirer side of the vault-kv interface."""

    egress_subnet: str = Field(
        description="Egress subnets to use separated by commas, in CIDR notation."
    )
    nonce: str = Field(
        description="Uniquely identifying value for this unit. `secrets.token_hex(16)` is recommended."
    )


class ProviderSchema(DataBagSchema):
    """The schema for the provider side of this interface."""

    app: VaultKvProviderSchema  # pyright: ignore[reportIncompatibleVariableOverride, reportGeneralTypeIssues]


class RequirerSchema(DataBagSchema):
    """The schema for the requirer side of this interface."""

    app: AppVaultKvRequirerSchema  # pyright: ignore[reportIncompatibleVariableOverride, reportGeneralTypeIssues]
    unit: UnitVaultKvRequirerSchema  # pyright: ignore[reportIncompatibleVariableOverride, reportGeneralTypeIssues]


@dataclass
class KVRequest:
    """This class represents a kv request from an interface Requirer."""

    relation: ops.Relation
    app_name: str
    unit_name: str
    mount_suffix: str
    egress_subnets: List[str]
    nonce: str


def get_egress_subnets_list_from_relation_data(relation_databag: Mapping[str, str]) -> List[str]:
    """Return the egress_subnet as a list.

    This function converts the string with values separated by commas to a list.

    Args:
        relation_databag: the relation databag of the unit or the app.
    """
    return [subnet.strip() for subnet in relation_databag.get("egress_subnet", "").split(",")]


def is_requirer_data_valid(app_data: Mapping[str, str], unit_data: Mapping[str, str]) -> bool:
    """Return whether the requirer data is valid."""
    try:
        RequirerSchema(
            app=AppVaultKvRequirerSchema(**app_data),
            unit=UnitVaultKvRequirerSchema(**unit_data),
        )
        return True
    except ValidationError as e:
        logger.debug("Invalid data: %s", e)
        return False


def is_provider_data_valid(data: Mapping[str, str]) -> bool:
    """Return whether the provider data is valid."""
    try:
        ProviderSchema(app=VaultKvProviderSchema(**data))  # type: ignore https://github.com/pydantic/pydantic/issues/8616
        return True
    except ValidationError as e:
        logger.debug("Invalid data: %s", e)
        return False


class VaultKvGoneAwayEvent(ops.EventBase):
    """VaultKvGoneAwayEvent Event."""

    pass


class VaultKvClientDetachedEvent(ops.EventBase):
    """VaultKvClientDetachedEvent Event."""

    def __init__(self, handle: ops.Handle, unit_name: str):
        super().__init__(handle)
        self.unit_name = unit_name

    def snapshot(self) -> Dict[str, Any]:
        """Return snapshot data that should be persisted."""
        return {
            "unit_name": self.unit_name,
        }

    def restore(self, snapshot: Dict[str, Any]) -> None:
        """Restore the event from a snapshot."""
        super().restore(snapshot)
        self.unit_name = snapshot["unit_name"]


class NewVaultKvClientAttachedEvent(ops.RelationEvent):
    """New vault kv client attached event."""

    def __init__(
        self,
        handle: ops.Handle,
        relation: ops.Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnets: List[str],
        nonce: str,
    ):
        super().__init__(handle, relation)
        self.relation_id = relation.id
        self.relation_name = relation.name
        self.app_name = app_name
        self.unit_name = unit_name
        self.mount_suffix = mount_suffix
        self.egress_subnets = egress_subnets
        self.nonce = nonce

    def snapshot(self) -> dict:
        """Return snapshot data that should be persisted."""
        return {
            "relation_id": self.relation_id,
            "relation_name": self.relation_name,
            "app_name": self.app_name,
            "unit_name": self.unit_name,
            "mount_suffix": self.mount_suffix,
            "egress_subnets": self.egress_subnets,
            "nonce": self.nonce,
        }

    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from a given snapshot."""
        super().restore(snapshot)
        self.relation_id = snapshot["relation_id"]
        self.app_name = snapshot["app_name"]
        self.unit_name = snapshot["unit_name"]
        self.mount_suffix = snapshot["mount_suffix"]
        self.egress_subnets = snapshot["egress_subnets"]
        self.nonce = snapshot["nonce"]


class VaultKvProviderEvents(ops.ObjectEvents):
    """List of events that the Vault Kv provider charm can leverage."""

    new_vault_kv_client_attached = ops.EventSource(NewVaultKvClientAttachedEvent)
    vault_kv_client_detached = ops.EventSource(VaultKvClientDetachedEvent)


class VaultKvProvides(ops.Object):
    """Class to be instantiated by the providing side of the relation."""

    on = VaultKvProviderEvents()  # type: ignore

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
    ) -> None:
        super().__init__(charm, relation_name)
        self.juju_facade = JujuFacade(charm)
        self.relation_name = relation_name
        self.framework.observe(
            charm.on[relation_name].relation_changed,
            self._on_relation_changed,
        )
        self.framework.observe(
            charm.on[relation_name].relation_departed,
            self._on_vault_kv_relation_departed,
        )

    def _on_relation_changed(self, event: ops.RelationChangedEvent):
        """Handle client changed relation.

        This handler will emit a new_vault_kv_client_attached event for each requiring unit
        with valid relation data.
        """
        if event.app is None:
            logger.debug("No remote application yet")
            return
        app_data = event.relation.data.get(event.app, {})
        if not event.unit:
            logger.debug("No unit in relation changed event")
            return
        unit_data = event.relation.data.get(event.unit, {})
        if not is_requirer_data_valid(app_data, unit_data):
            logger.debug("Invalid data from unit %r", event.unit.name)
            return
        self.on.new_vault_kv_client_attached.emit(
            relation=event.relation,
            app_name=event.app.name,
            unit_name=event.unit.name,
            mount_suffix=app_data.get("mount_suffix"),
            egress_subnets=get_egress_subnets_list_from_relation_data(unit_data),
            nonce=unit_data.get("nonce"),
        )

    def _on_vault_kv_relation_departed(self, event: ops.RelationDepartedEvent):
        """Handle relation departed."""
        if event.departing_unit:
            self.on.vault_kv_client_detached.emit(unit_name=event.departing_unit.name)

    def remove_unit_credentials(self, relation: ops.Relation, nonce: str | Iterable[str]):
        """Remove nonce(s) from the relation."""
        if isinstance(nonce, str):
            nonce = [nonce]

        credentials = self.get_credentials(relation)

        for n in nonce:
            credentials.pop(n, None)

        try:
            self.juju_facade.set_app_relation_data(
                name=self.relation_name,
                relation=relation,
                data={"credentials": json.dumps(credentials, sort_keys=True)},
            )
        except NotLeaderError:
            return

    def get_credentials(self, relation: ops.Relation) -> dict:
        """Get the unit credentials from the app relation data and load it as a dict."""
        return json.loads(
            self.juju_facade.get_app_relation_data(
                name=self.relation_name,
                relation=relation,
            ).get("credentials", "{}")
        )

    def get_kv_requests(self, relation_id: int | None = None) -> List[KVRequest]:
        """Get all KV requests for the relation."""
        kv_requests: List[KVRequest] = []
        relations = self.juju_facade.get_active_relations(self.relation_name, relation_id)
        for relation in relations:
            app_data = self.juju_facade.get_remote_app_relation_data(
                self.relation_name, relation.id
            )
            for unit in relation.units:
                unit_data = self.juju_facade.get_remote_unit_relation_data(
                    name=self.relation_name,
                    id=relation.id,
                    unit=unit,
                )
                if not is_requirer_data_valid(app_data, unit_data):
                    continue
                kv_requests.append(
                    KVRequest(
                        relation=relation,
                        app_name=relation.app.name,
                        unit_name=unit.name,
                        mount_suffix=app_data["mount_suffix"],
                        egress_subnets=get_egress_subnets_list_from_relation_data(unit_data),
                        nonce=unit_data["nonce"],
                    )
                )
        return kv_requests

    def set_kv_data(
        self,
        relation: ops.Relation,
        mount: str,
        ca_certificate: str,
        vault_url: str,
        nonce: str,
        credentials_juju_secret_id: str,
    ):
        """Set the kv data on the relation."""
        credentials = self.get_credentials(relation)
        credentials[nonce] = credentials_juju_secret_id
        try:
            self.juju_facade.set_app_relation_data(
                name=self.relation_name,
                id=relation.id,
                data={
                    "mount": mount,
                    "ca_certificate": ca_certificate,
                    "vault_url": vault_url,
                    "credentials": json.dumps(credentials, sort_keys=True),
                },
            )
        except NotLeaderError:
            return


class VaultKvBaseEvent(ops.RelationEvent):
    """Base class for VaultKV requirer events."""

    def __init__(
        self, handle: ops.Handle, relation_id: int, relation_name: str, relation: ops.Relation
    ):
        super().__init__(handle, relation)
        self.relation_id = relation_id
        self.relation_name = relation_name

    def snapshot(self) -> dict:
        """Return snapshot data that should be persisted."""
        return dict(
            super().snapshot(),
            relation_id=self.relation_id,
            relation_name=self.relation_name,
        )

    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from a given snapshot."""
        super().restore(snapshot)
        self.relation_id = snapshot["relation_id"]
        self.relation_name = snapshot["relation_name"]


class VaultKvConnectedEvent(VaultKvBaseEvent):
    """VaultKvConnectedEvent Event."""

    pass


class VaultKvReadyEvent(VaultKvBaseEvent):
    """VaultKvReadyEvent Event."""

    pass


class VaultKvRequireEvents(ops.ObjectEvents):
    """List of events that the Vault Kv requirer charm can leverage."""

    connected = ops.EventSource(VaultKvConnectedEvent)
    ready = ops.EventSource(VaultKvReadyEvent)
    gone_away = ops.EventSource(VaultKvGoneAwayEvent)


class VaultKvRequires(ops.Object):
    """Class to be instantiated by the requiring side of the relation."""

    on = VaultKvRequireEvents()  # type: ignore

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str,
        mount_suffix: str,
    ) -> None:
        super().__init__(charm, relation_name)
        self.charm = charm
        self.juju_facade = JujuFacade(charm)
        self.relation_name = relation_name
        self.mount_suffix = mount_suffix
        self.framework.observe(
            self.charm.on[relation_name].relation_joined,
            self._handle_relation,
        )
        self.framework.observe(
            self.charm.on.config_changed,
            self._handle_relation,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_vault_kv_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken,
            self._on_vault_kv_relation_broken,
        )

    def _handle_relation(self, _: ops.EventBase):
        """Run when a new unit joins the relation or when the address of the unit changes.

        Set the secret backend in the application databag if we are the leader.
        Emit the connected event.
        """
        try:
            relations = self.juju_facade.get_relations(self.relation_name)
        except NoSuchRelationError:
            return
        if not relations:
            return
        for relation in relations:
            try:
                self.juju_facade.set_app_relation_data(
                    name=self.relation_name,
                    relation=relation,
                    data={"mount_suffix": self.mount_suffix},
                )
            except NotLeaderError:
                logger.debug("Not leader, not setting mount_suffix")
                pass
            self.on.connected.emit(
                relation.id,
                relation.name,
                relation,
            )

    def _on_vault_kv_relation_changed(self, event: ops.RelationChangedEvent):
        """Handle relation changed."""
        if event.app is None:
            logger.debug("No remote application yet")
            return

        if (
            is_provider_data_valid(event.relation.data[event.app])
            and self.get_unit_credentials(event.relation) is not None
        ):
            self.on.ready.emit(
                event.relation.id,
                event.relation.name,
                event.relation,
            )

    def _on_vault_kv_relation_broken(self, event: ops.RelationBrokenEvent):
        """Handle relation broken."""
        self.on.gone_away.emit()

    def request_credentials(
        self, relation: ops.Relation, egress_subnet: List[str] | str, nonce: str
    ) -> None:
        """Request credentials from the vault-kv relation.

        Credentials are tied to the unit egress_subnet, so if the egress_subnet
        changes a new secret id must be generated.

        A change in egress_subnets can happen when the pod is rescheduled to a different
        node by the underlying substrate without a change from Juju.

        Args:
            relation: The relation object or the relation id.
            egress_subnet: The egress subnets requesting the credentials for.
            nonce: The nonce that identifies the unit.
        """
        if isinstance(egress_subnet, str):
            egress_subnet = [egress_subnet]
        self.juju_facade.set_unit_relation_data(
            name=self.relation_name,
            relation=relation,
            data={"egress_subnet": ",".join(egress_subnet), "nonce": nonce},
        )

    def get_vault_url(self, relation: ops.Relation) -> str | None:
        """Return the vault_url from the relation."""
        return relation.data[relation.app].get("vault_url")

    def get_ca_certificate(self, relation: ops.Relation) -> str | None:
        """Return the ca_certificate from the relation."""
        return relation.data[relation.app].get("ca_certificate")

    def get_mount(self, relation: ops.Relation) -> str | None:
        """Return the mount from the relation."""
        return relation.data[relation.app].get("mount")

    def get_unit_credentials(self, relation: ops.Relation) -> str | None:
        """Return the unit credentials from the relation.

        Unit credentials are stored in the relation data as a Juju secret id.
        """
        nonce = relation.data[self.charm.unit].get("nonce")
        if nonce is None or relation.app is None:
            return None
        return json.loads(relation.data[relation.app].get("credentials", "{}")).get(nonce)
