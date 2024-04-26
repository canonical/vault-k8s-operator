#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for the vault-autounseal relation.

This library contains the Requires and Provides classes for handling the
vault-autounseal interface.

The provider side of the interface is responsible for enabling the vault
transit engine and creating the necessary keys and policies for an external
vault to be able to autounseal itself.

The requirer side of the interface is responsible for retrieving the necessary
details to autounseal the vault instance, and configuring the vault instance to
use them.

## Getting Started

From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.vault_k8s.v0.vault_autounseal
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
juju integrate <vault a>:vault-autounseal-provides <vault b>:vault-autounseal-requires
```

where `vault a` is the Vault app which will provide the autounseal service, and
`vault b` is the Vault app which will be configured for autounseal via `vault a`.
"""

import logging
from typing import Any, Dict, Optional

import ops
from interface_tester import DataBagSchema
from ops import RelationDataContent, model  # type: ignore
from pydantic import BaseModel, Field, ValidationError

# The unique Charmhub library identifier, never change it
LIBID = "c33e0a12506444e2b644ac2893ac9394"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class LogAdapter(logging.LoggerAdapter):
    """Adapter for the logger to prepend a prefix to all log lines."""

    prefix = "vault_autounseal"

    def process(self, msg, kwargs):
        """Decides the format for the prepended text."""
        return f"[{self.prefix}] {msg}", kwargs


logger = LogAdapter(logging.getLogger(__name__), {})


class VaultAutounsealProviderSchema(BaseModel):
    """Provider side of the vault-autounseal relation interface."""

    address: str = Field(description="The address of the Vault server to connect to.")
    credentials_secret_id: str = Field(
        description=(
            "The secret id of the Juju secret which stores the credentials for authenticating with the Vault server."
        )
    )
    ca_certificate: str = Field(
        description="The CA certificate to use when validating the Vault server's certificate."
    )


class ProviderSchema(DataBagSchema):
    """The schema for the provider side of this interface."""

    app: VaultAutounsealProviderSchema  # type: ignore


class VaultAutounsealDetailsReadyEvent(ops.EventBase):
    """Event emitted when the vault autounseal details are ready in the databag."""

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


class VaultAutounsealInitialize(ops.EventBase):
    """Event emitted when Vault autounseal should be initialized for a new application."""

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
                f"Unable to restore {self}: relation {snapshot['relation_name']} (id={snapshot['relation_id']}) not found."
            )
        self.relation = relation


class VaultAutounsealDestroy(ops.EventBase):
    """Event emitted when Vault autounseal configuration for a relation should be destroyed."""

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
                f"Unable to restore {self}: relation {snapshot['relation_name']} (id={snapshot['relation_id']}) not found."
            )
        self.relation = relation


class VaultAutounsealProvidesEvents(ops.ObjectEvents):
    """Events raised by the vault-autounseal relation on the provider side."""

    vault_autounseal_initialize = ops.EventSource(VaultAutounsealInitialize)
    vault_autounseal_destroy = ops.EventSource(VaultAutounsealDestroy)


class VaultAutounsealRequireEvents(ops.ObjectEvents):
    """Events raised by the vault-autounseal relation on the requirer side."""

    vault_autounseal_details_ready = ops.EventSource(VaultAutounsealDetailsReadyEvent)


class VaultAutounsealProvides(ops.Object):
    """Manages the vault-autounseal relation from the provider side."""

    on: VaultAutounsealProvidesEvents = VaultAutounsealProvidesEvents()  # type: ignore

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
        self.on.vault_autounseal_initialize.emit(relation=event.relation)

    def _on_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        self.on.vault_autounseal_destroy.emit(relation=event.relation)

    def _create_autounseal_credentials_secret(
        self, relation: ops.Relation, role_id: str, secret_id: str
    ) -> str:
        """Create a Juju secret with the autounseal credentials.

        Args:
            relation: The relation to grant access to the secret.
            role_id: The role id to store in the secret.
            secret_id: The secret id to store in the secret.

        Returns:
            The secret id of the created secret.
        """
        secret = self.charm.app.add_secret(
            {
                "role-id": role_id,
                "secret-id": secret_id,
            },
        )
        secret.grant(relation)
        if secret.id is None:
            raise ValueError("Secret id is None")
        return secret.id

    def set_autounseal_data(
        self,
        relation: ops.Relation,
        vault_address: str,
        approle_id: str,
        approle_secret_id: str,
        ca_certificate: str,
    ) -> None:
        """Set the autounseal data in the relation databag.

        Args:
            relation: The Juju relation to set the autounseal data in.
            vault_address: The address of the Vault server.
            approle_id: The approle id to use when authenticating with the Vault server.
            approle_secret_id: The approle secret id to use when authenticating with the Vault server.
            ca_certificate: The CA certificate to use when validating the Vault server's certificate.
        """
        if not self.charm.unit.is_leader():
            logger.warning(
                "Attempting to set the autounseal data without being the leader. Ignoring the request."
            )
            return
        if relation is None:
            logger.warning("No relation found")
            return
        if not relation.active:
            logger.warning("Relation is not active")
            return
        credentials_secret_id = self._create_autounseal_credentials_secret(
            relation, approle_id, approle_secret_id
        )
        relation.data[self.charm.app].update(
            {
                "address": vault_address,
                "credentials_secret_id": credentials_secret_id,
                "ca_certificate": ca_certificate,
            }
        )


def is_provider_data_valid(data: RelationDataContent) -> bool:
    """Return whether the provider data is valid.

    This uses the pydantic schema to validate the data.

    Args:
        data: The data to validate.

    Returns:
        True if the data is valid, False otherwise.
    """
    try:
        ProviderSchema(app=VaultAutounsealProviderSchema(**data))
        return True
    except ValidationError as e:
        logger.warning("Invalid data: %s", e)
        return False


class VaultAutounsealRequires(ops.Object):
    """Manages the vault-autounseal relation from the requirer side."""

    on: VaultAutounsealRequireEvents = VaultAutounsealRequireEvents()  # type: ignore

    def __init__(self, charm: ops.CharmBase, relation_name: str):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name

        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        if is_provider_data_valid(event.relation.data[event.app]):
            self.on.vault_autounseal_details_ready.emit(event.relation)

    def get_vault_url(self) -> Optional[str]:
        """Return the vault url from the relation databag.

        Args:
            relation: The relation from which to get the vault url.

        Returns:
            The vault url if it exists, None otherwise.
        """
        relation = self.framework.model.get_relation(self.relation_name)
        if not relation:
            logger.warning("Relation is not set")
            return None
        if not relation.active:
            logger.warning("Relation is not active")
            return None
        if relation.app is None:
            logger.warning("No remote application yet")
            return None
        return relation.data[relation.app].get("address")

    def get_credentials(self) -> tuple[str | None, str | None] | None:
        """Return the token from the Juju secret.

        Args:
            credentials_secret_id: The secret id of the Juju secret which stores the credentials for authenticating with the Vault server.

        Returns:
            A tuple containing the role id and secret id
        """
        relation = self.framework.model.get_relation(self.relation_name)
        if not relation:
            logger.warning("Relation is not set")
            return None
        if not relation.active:
            logger.warning("Relation is not active")
            return None
        if relation.app is None:
            logger.warning("No remote application yet")
            return None
        credentials_secret_id = relation.data[relation.app].get("credentials_secret_id")
        secret_content = self.model.get_secret(id=credentials_secret_id).get_content(refresh=True)
        return (secret_content.get("role-id"), secret_content.get("secret-id"))

    def get_ca_certificate(self) -> Optional[str]:
        """Return the ca_certificate from the relation.

        Args:
            relation: The relation from which to get the ca_certificate.

        Returns:
            The ca certificate if it exists, None otherwise.
        """
        relation = self.framework.model.get_relation(self.relation_name)
        if not relation:
            logger.warning("Relation is not set")
            return None
        if not relation.active:
            logger.warning("Relation is not active")
            return None
        if relation.app is None:
            logger.warning("No remote application yet")
            return None
        return relation.data[relation.app].get("ca_certificate")
