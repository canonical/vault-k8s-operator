"""Library for the vault-transit relation.

This library contains the Requires and Provides classes for handling the
vault-transit interface.

## Getting Started

From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.vault_k8s.v0.vault_transit
```

### Provider charm

The provider charm is the charm that provides a Vault instance that can be
used to autounseal other Vault instances via the Vault transit backend.

### Requirer charm

The requirer charm is the charm that wishes to autounseal a Vault instance via
the Vault transit backend.

### Integration

You can integrate both charms by running:

```bash
juju integrate <vault provider charm> <vault requirer charm>
```
"""

import logging
from typing import Any, Dict, Optional

import ops
from interface_tester import DataBagSchema
from ops import RelationDataContent, model  # type: ignore
from pydantic import BaseModel, Field, ValidationError

# The unique Charmhub library identifier, never change it
LIBID = "1cf22afd77974266af15dec760fe956f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class VaultTransitProviderSchema(BaseModel):
    """Provider side of the vault-transit relation interface."""

    address: str = Field(description="The address of the Vault server to connect to.")
    token_secret_id: str = Field(
        description=(
            "The secret id of the Juju secret which stores is token for authenticating with the Vault server."
        )
    )


class ProviderSchema(DataBagSchema):
    """The schema for the provider side of this interface."""

    app: VaultTransitProviderSchema  # type: ignore


class VaultTransitDetailsReadyEvent(ops.EventBase):
    """Event emitted when the vault transit details are ready in the databag."""

    def __init__(self, handle: ops.Handle, relation: model.Relation):
        super().__init__(handle)
        self.relation = relation

    def snapshot(self) -> Dict[str, Any]:
        """Return snapshot data that should be persisted."""
        return dict(
            super().snapshot(),
            relation_id=self.relation.id,
            relation_name=self.relation.name,
        )

    def restore(self, snapshot: Dict[str, Any]) -> None:
        """Restore the event from a snapshot."""
        super().restore(snapshot)
        relation = self.framework.model.get_relation(
            snapshot["relation_name"], snapshot["relation_id"]
        )
        if relation is None:
            raise ValueError(
                "Unable to restore {}: relation {} (id={}) not found.".format(
                    self, snapshot["relation_name"], snapshot["relation_id"]
                )
            )
        self.relation = relation


class VaultTransitEnableAutounseal(ops.EventBase):
    """Event emitted when the vault transit engine should be started."""

    def __init__(self, handle: ops.Handle, relation: model.Relation):
        super().__init__(handle)
        self.relation = relation

    def snapshot(self) -> Dict[str, Any]:
        """Return snapshot data that should be persisted."""
        return dict(
            super().snapshot(),
            relation_id=self.relation.id,
            relation_name=self.relation.name,
        )

    def restore(self, snapshot: Dict[str, Any]) -> None:
        """Restore the event from a snapshot."""
        super().restore(snapshot)
        relation = self.framework.model.get_relation(
            snapshot["relation_name"], snapshot["relation_id"]
        )
        if relation is None:
            raise ValueError(
                "Unable to restore {}: relation {} (id={}) not found.".format(
                    self, snapshot["relation_name"], snapshot["relation_id"]
                )
            )
        self.relation = relation


class VaultTransitProvidesEvents(ops.ObjectEvents):
    """Events raised by the vault-transit relation on the provider side."""

    vault_transit_enable_autounseal = ops.EventSource(VaultTransitEnableAutounseal)


class VaultTransitRequireEvents(ops.ObjectEvents):
    """Events raised by the vault-transit relation on the requirer side."""

    vault_transit_details_ready = ops.EventSource(VaultTransitDetailsReadyEvent)


class VaultTransitProvides(ops.Object):
    """Manages the vault-transit relation from the provider side."""

    on: VaultTransitProvidesEvents = VaultTransitProvidesEvents()  # type: ignore

    def __init__(self, charm: ops.CharmBase, relation_name: str):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

        self.framework.observe(
            self.charm.on[relation_name].relation_created, self._on_relation_created
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken, self._on_relation_broken
        )

    def _on_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        self.on.vault_transit_enable_autounseal.emit(relation=event.relation)

    def _on_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        # TODO Delete the key from the transit backend

        # TODO: Delete the policy from the transit backend
        return

    def set_vault_url(self, relation: ops.Relation, address: str) -> None:
        """Set the vault_url in the relation."""
        if not self.charm.unit.is_leader():
            return
        relation.data[self.charm.app].update({"address": address})

    def set_credentials_secret_id(self, relation: ops.Relation, token_secret_id: str) -> None:
        """Set the token secret id in the relation."""
        if relation.app is None:
            raise ValueError("The `relation.app` is not set")
        relation.data[self.charm.app].update({"credentials_secret_id": token_secret_id})

    def create_token_secret(self, token: str) -> str:
        """Create a Juju secret with the token."""
        secret = self.model.app.add_secret({"token": token})
        if secret.id is None:
            raise ValueError("The `secret.id` is not set")
        return secret.id

    def set_ca_certificate(self, relation: ops.Relation, ca_certificate: str):
        """Set the ca_certificate on the relation."""
        if not self.charm.unit.is_leader():
            return
        if not relation:
            logger.warning("Relation is None")
            return
        if not relation.active:
            logger.warning("Relation is not active")
            return
        relation.data[self.charm.app]["ca_certificate"] = ca_certificate


def is_provider_data_valid(data: RelationDataContent) -> bool:
    """Return whether the provider data is valid."""
    try:
        ProviderSchema(app=VaultTransitProviderSchema(**data))
        return True
    except ValidationError as e:
        logger.debug("Invalid data: %s", e)
        return False


class VaultTransitRequires(ops.Object):
    """Manages the vault-transit relation from the requirer side."""

    on: VaultTransitRequireEvents = VaultTransitRequireEvents()  # type: ignore

    def __init__(self, charm: ops.CharmBase, relation_name: str):
        super().__init__(charm, relation_name)
        self.relation = relation_name

        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)
        self.framework.observe(charm.on[relation_name].relation_broken, self._on_relation_broken)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        if event.app is None:
            logger.debug("No remote application yet")
        if is_provider_data_valid(event.relation.data[event.app]):
            self.on.vault_transit_details_ready.emit(event.relation)

    def _on_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        # TODO: Seal the vault
        return

    def get_vault_url(self, relation: ops.Relation) -> Optional[str]:
        """Return the vault_url from the relation."""
        if relation.app is None:
            return None
        return relation.data[relation.app].get("address")

    @staticmethod
    def get_credentials_secret_id(relation: ops.Relation) -> Optional[str]:
        """Return the token secret id from the relation."""
        if relation.app is None:
            return None
        return relation.data[relation.app].get("credentials_secret_id")

    def get_credentials(self, credentials_secret_id: str) -> tuple[str | None, str | None]:
        """Return the token from the Juju secret."""
        secret_content = self.model.get_secret(id=credentials_secret_id).get_content(refresh=True)
        return (secret_content.get("role-id"), secret_content.get("secret-id"))

    def get_credentials_from_relation(
        self, relation: ops.Relation
    ) -> tuple[str | None, str | None] | None:
        """Return the credentials from the relation."""
        token_secret_id = VaultTransitRequires.get_credentials_secret_id(relation)
        return self.get_credentials(token_secret_id) if token_secret_id else None

    def get_ca_certificate(self, relation: ops.Relation) -> Optional[str]:
        """Return the ca_certificate from the relation."""
        if not relation:
            logger.warning("Relation is not set")
            return None
        if not relation.active:
            logger.warning("Relation is not active")
            return None
        return relation.data[relation.app].get("ca_certificate")
