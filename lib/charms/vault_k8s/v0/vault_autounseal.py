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

Add the following to `metadata.yaml`:

```yaml
provides:
  vault-autounseal-provides:
    interface: vault-autounseal
```

### Requirer charm

The requirer charm is the charm that wishes to autounseal a Vault instance via
the Vault transit backend.

Add the following to `metadata.yaml`:

```yaml
requires:
  vault-autounseal-requires:
    interface: vault-autounseal
    limit: 1
```

### Integration

You can integrate both charms by running:

```bash
juju integrate <vault a>:vault-autounseal-provides <vault b>:vault-autounseal-requires
```

where `vault a` is the Vault app which will provide the autounseal service, and
`vault b` is the Vault app which will be configured for autounseal via `vault a`.
"""

import logging
from collections import namedtuple
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import ops
from interface_tester import DataBagSchema
from ops import Relation, RelationDataContent, SecretNotFoundError, model  # type: ignore
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

    def __init__(self, handle: ops.Handle, address, role_id, secret_id, ca_certificate):
        super().__init__(handle)
        self.address = address
        self.role_id = role_id
        self.secret_id = secret_id
        self.ca_certificate = ca_certificate

    def snapshot(self) -> Dict[str, Any]:
        """Return snapshot data that should be persisted."""
        return dict(
            super().snapshot(),
            address=self.address,
            role_id=self.role_id,
            secret_id=self.secret_id,
            ca_certificate=self.ca_certificate,
        )

    def restore(self, snapshot: Dict[str, Any]) -> None:
        """Restore the event from a snapshot."""
        super().restore(snapshot)
        self.address = snapshot["address"]
        self.role_id = snapshot["role_id"]
        self.secret_id = snapshot["secret_id"]
        self.ca_certificate = snapshot["ca_certificate"]


class VaultAutounsealProviderRemoved(ops.EventBase):
    """Event emitted when the vault that provided autounseal capabilities is removed."""


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
    vault_autounseal_provider_removed = ops.EventSource(VaultAutounsealProviderRemoved)


ApproleDetails = namedtuple("ApproleDetails", ["role_id", "secret_id"])


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

    def get_outstanding_requests(self, relation_id: Optional[int] = None) -> List[Relation]:
        """Get the outstanding requests for the relation."""
        outstanding_requests: List[Relation] = []
        requirer_requests = self.get_requirer_requests(relation_id=relation_id)
        for relation in requirer_requests:
            if not self._credentials_issued_for_request(relation_id=relation.id):
                outstanding_requests.append(relation)
        return outstanding_requests

    def get_requirer_requests(self, relation_id: Optional[int] = None) -> List[Relation]:
        """Get all requests for the relation."""
        relations = (
            [
                relation
                for relation in self.model.relations[self.relation_name]
                if relation.id == relation_id
            ]
            if relation_id is not None
            else self.model.relations.get(self.relation_name, [])
        )
        return [relation for relation in relations if relation.active]

    def _credentials_issued_for_request(self, relation_id: Optional[int]) -> bool:
        """Return whether credentials have been issued for the request."""
        relation = self.model.get_relation(self.relation_name, relation_id)
        if not relation:
            return False
        credentials = self._get_credentials(relation)
        return all(credentials)

    def _get_credentials(self, relation: ops.Relation) -> ApproleDetails:
        """Return the credentials from the Juju secret.

        Args:
            relation: The relation to get the credentials for.

        Returns:
            A tuple containing the role id and secret id
        """
        if not relation.active:
            logger.warning("Relation is not active")
            return ApproleDetails(None, None)
        if relation.app is None:
            logger.warning("No remote application yet")
            return ApproleDetails(None, None)
        credentials_secret_id = relation.data[relation.app].get("credentials_secret_id")
        if credentials_secret_id is None:
            return ApproleDetails(None, None)
        try:
            secret_content = self.model.get_secret(id=credentials_secret_id).get_content(
                refresh=True
            )
        except SecretNotFoundError:
            logger.warning("Secret not found")
            return ApproleDetails(None, None)

        return ApproleDetails(secret_content.get("role-id"), secret_content.get("secret-id"))


def get_transit_key_name(relation_id: int) -> str:
    """Return the transit key name for the given relation id.

    Args:
        relation_id: The id of the relation for which to get the transit key name.

    Returns:
        The transit key name.
    """
    return f"{relation_id}"


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


@dataclass
class AutounsealDetails:
    """The details required to autounseal a vault instance."""

    address: str | None
    role_id: str | None
    secret_id: str | None
    ca_certificate: str | None


class VaultAutounsealRequires(ops.Object):
    """Manages the vault-autounseal relation from the requirer side."""

    on: VaultAutounsealRequireEvents = VaultAutounsealRequireEvents()  # type: ignore

    def __init__(self, charm: ops.CharmBase, relation_name: str):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name

        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)
        self.framework.observe(charm.on[relation_name].relation_broken, self._on_relation_broken)

    def _on_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        data = event.relation.data[event.app]
        if is_provider_data_valid(data):
            details = self.get_details()
            self.on.vault_autounseal_details_ready.emit(
                details.address, details.role_id, details.secret_id, details.ca_certificate
            )

    def _on_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        self.on.vault_autounseal_provider_removed.emit()

    def get_details(self) -> AutounsealDetails:
        """Return the vault address, role id, secret id and ca certificate from the relation databag.

        Returns:
            A tuple containing the vault address, role id, secret id and ca certificate.
        """
        relation = self.framework.model.get_relation(self.relation_name)
        if not relation:
            logger.warning("Relation is not set")
            return AutounsealDetails(None, None, None, None)
        if not relation.active:
            logger.warning("Relation is not active")
            return AutounsealDetails(None, None, None, None)
        if relation.app is None:
            logger.warning("No remote application yet")
            return AutounsealDetails(None, None, None, None)
        data = relation.data[relation.app]
        credentials = self._get_credentials(relation)
        return AutounsealDetails(
            data.get("address"),
            credentials.role_id,
            credentials.secret_id,
            data.get("ca_certificate"),
        )

    def _get_credentials(self, relation: ops.Relation) -> ApproleDetails:
        """Return the token from the Juju secret.

        Returns:
            A tuple containing the role id and secret id
        """
        if not relation.active:
            logger.warning("Relation is not active")
            return ApproleDetails(None, None)
        if relation.app is None:
            logger.warning("No remote application yet")
            return ApproleDetails(None, None)
        credentials_secret_id = relation.data[relation.app].get("credentials_secret_id")
        secret_content = self.model.get_secret(id=credentials_secret_id).get_content(refresh=True)
        return ApproleDetails(secret_content.get("role-id"), secret_content.get("secret-id"))
