"""This library provides a wrapper of the Juju API."""

import logging
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import Any, List, Literal, cast

from ops.charm import CharmBase
from ops.model import (
    Application,
    Binding,
    ModelError,
    Port,
    Relation,
    RelationDataContent,
    RelationDataError,
    Secret,
    SecretNotFoundError,
    Unit,
)

logger = logging.getLogger(__name__)


class FacadeError(Exception):
    """Base class for custom errors raised by this library."""

    def __init__(self, message: Any = None, *args: Any) -> None:
        super().__init__(message, *args)
        self.message = str(message) if message is not None else ""


class TransientJujuError(FacadeError):
    """Exception raised for transient Juju errors like ModelError."""


class SecretValidationError(FacadeError):
    """Exception raised for secret validation errors."""


class NoSuchSecretError(FacadeError):
    """Exception raised when a secret does not exist."""


class SecretRemovedError(FacadeError):
    """Exception raised when a secret does not exist anymore."""


class NoSuchRelationError(FacadeError):
    """Exception raised when a relation does not exist."""


class InvalidRelationDataError(FacadeError):
    """Exception raised when relation data is invalid."""


class NotLeaderError(FacadeError):
    """Exception raised when the unit is not leader."""


class NoSuchStorageError(FacadeError):
    """Exception raised when a storage does not exist."""


class SecretAccessDeniedError(FacadeError):
    """Exception raised if the charm does not have permission to access the secret."""


class NoRemoteAppError(FacadeError):
    """Exception raised when a relation has no remote application."""


class MultipleRelationsFoundError(FacadeError):
    """Exception raised when multiple relations are found."""


class JujuFacade:
    """Juju API wrapper class."""

    def __init__(self, charm: CharmBase):
        self.charm = charm

    def set_unit_ports(self, *ports: int | Port) -> None:
        """Set the ports for the unit.

        This enables Juju to open the ports in the firewall if needed when
        `juju expose` is used.
        """
        return self.charm.unit.set_ports(*ports)

    # Secret related methods
    def get_secret(self, label: str | None = None, id: str | None = None) -> Secret:
        """Retrieve a secret and handles error.

        Raises:
            NoSuchSecretError: if the secret does not exist
            TransientJujuError: if there is a Juju ModelError
        """
        if not label and not id:
            raise ValueError("Either label or id must be provided")
        try:
            return (
                self.charm.model.get_secret(id=id)
                if id
                else self.charm.model.get_secret(label=label)
            )
        except SecretNotFoundError as e:
            logger.warning("Secret %s not found: %s", label, e)
            raise NoSuchSecretError(e) from e
        except ModelError as e:
            logger.error("Error getting secret %s: %s", label, e)
            raise TransientJujuError(e) from e

    def secret_exists(self, label: str | None = None, id: str | None = None) -> bool:
        """Check if the secret exists.

        Raises:
            TransientJujuError
        """
        try:
            self.get_secret(label=label, id=id)
            return True
        except NoSuchSecretError:
            return False

    def secret_exists_with_fields(
        self, fields: tuple[str, ...], label: str | None = None, id: str | None = None
    ) -> bool:
        """Check if the secret exists and has the required fields.

        Args:
            fields: The requested fields
            label: The secret label
            id: The secret id

        Returns:
            True if the secret exists and has the required fields, False otherwise

        Raises:
            TransientJujuError
        """
        try:
            secret_content = self._get_secret_content(label=label, id=id)
            return all(secret_content.get(field) for field in fields)
        except (NoSuchSecretError, SecretRemovedError):
            return False

    def _get_secret_content(
        self, label: str | None = None, id: str | None = None, refresh: bool = False
    ) -> dict[str, str]:
        try:
            secret = self.get_secret(label=label, id=id)
            return secret.get_content(refresh=refresh)
        except NoSuchSecretError:
            raise
        except SecretNotFoundError as e:
            raise SecretRemovedError(e) from e
        except ModelError as e:
            raise SecretAccessDeniedError(e) from e

    def get_current_secret_content(
        self, label: str | None = None, id: str | None = None
    ) -> dict[str, str]:
        """Get secret content if the secret exists and return currently tracked revision.

        Raises:
            TransientJujuError
            NoSuchSecretError
            SecretRemovedError
        """
        return self._get_secret_content(label=label, id=id)

    def get_latest_secret_content(
        self, label: str | None = None, id: str | None = None
    ) -> dict[str, str]:
        """Get secret content if the secret exists and return latest revision.

        Raises:
            TransientJujuError
            NoSuchSecretError
            SecretRemovedError
        """
        return self._get_secret_content(label=label, id=id, refresh=True)

    def get_secret_content_values(
        self, *keys: str, label: str | None = None, id: str | None = None
    ) -> tuple[str | None, ...]:
        """Get secret content values by keys.

        Args:
            keys: Keys of the requested values
            label: The secret label
            id: The secret id

        Returns:
            tuple[str | None, ...]: The secret content values,
            if a key is not found, None is returned for its value

        Raises:
            TransientJujuError
            NoSuchSecretError
            SecretRemovedError
        """
        secret_content = self._get_secret_content(label=label, id=id)
        for key in keys:
            if key not in secret_content:
                logger.warning("Secret %s does not have key %s", label or id, key)
        return tuple(secret_content.get(key, None) for key in keys)

    def _add_app_secret(
        self,
        content: dict[str, str],
        label: str | None = None,
        description: str | None = None,
    ) -> Secret:
        """Add a secret to the application."""
        try:
            secret = self.charm.app.add_secret(content, label=label, description=description)
            secret.get_content(refresh=True)
            logger.info("Secret %s added to application", label or secret.id)
            return secret
        except ValueError as e:
            raise SecretValidationError(e) from e

    def _add_unit_secret(
        self,
        content: dict[str, str],
        label: str | None = None,
        description: str | None = None,
    ) -> Secret:
        """Add a secret to the unit."""
        try:
            secret = self.charm.unit.add_secret(content, label=label, description=description)
            secret.get_content(refresh=True)
            logger.info("Secret %s added to unit", label or secret.id)
            return secret
        except ValueError as e:
            raise SecretValidationError(e) from e

    def _create_secret(
        self,
        content: dict[str, str],
        label: str | None = None,
        unit_or_app: Literal["unit", "app"] = "app",
    ) -> Secret:
        if unit_or_app == "app":
            return self._add_app_secret(content, label)
        return self._add_unit_secret(content, label)

    def _set_secret_content(
        self,
        content: dict[str, str],
        label: str | None = None,
        id: str | None = None,
        unit_or_app: Literal["unit", "app"] = "app",
        description: str | None = None,
    ) -> Secret:
        if not label and not id:
            return self._create_secret(content, label, unit_or_app)
        try:
            secret = self.get_secret(label=label, id=id)
            latest_content = self.get_latest_secret_content(label=label, id=id)
        except (NoSuchSecretError, SecretRemovedError):
            return self._create_secret(content, label, unit_or_app)
        try:
            if latest_content == content:
                logger.info(
                    "Secret %s already has the requested content, skipping",
                    label or secret.id,
                )
                return secret
            logger.info("Setting secret content to %s", label or secret.id)
            secret.set_content(content)
            return secret
        except ModelError as e:
            raise TransientJujuError(e) from e
        except ValueError as e:
            raise SecretValidationError(e) from e

    def set_app_secret_content(
        self,
        content: dict[str, str],
        label: str | None = None,
        id: str | None = None,
        description: str | None = None,
    ) -> Secret:
        """Set the secret content if the secret exists.

        Creates new secret revision if secret exists, otherwise creates a new secret.

        Raises:
            TransientJujuError
            SecretValidationError
        """
        return self._set_secret_content(
            content=content,
            label=label,
            id=id,
            unit_or_app="app",
            description=description,
        )

    def set_unit_secret_content(
        self,
        content: dict[str, str],
        label: str,
        id: str | None = None,
        description: str | None = None,
    ) -> Secret:
        """Set the secret content if the secret exists.

        Creates new secret revision if secret exists, otherwise creates a new secret.

        Raises:
            TransientJujuError
            SecretValidationError
        """
        return self._set_secret_content(
            content=content,
            label=label,
            id=id,
            unit_or_app="unit",
            description=description,
        )

    def set_secret_label(self, new_label: str, label: str, id: str | None = None) -> None:
        """Set a new label for the secret if the secret exists.

        Raises:
            TransientJujuError
        """
        secret = self.get_secret(label=label, id=id)
        secret.set_info(label=new_label)

    def set_secret_expiry(self, expiry: datetime, label: str, id: str | None = None) -> None:
        """Set a new expiry date for the secret if the secret exists.

        Raises:
            TransientJujuError
        """
        secret = self.get_secret(label=label, id=id)
        secret.set_info(expire=expiry)

    def grant_secret(
        self,
        relation: Relation,
        secret: Secret | None = None,
        secret_id: str | None = None,
        secret_label: str | None = None,
    ) -> None:
        """Grant read access to the secret to the application related.

        If secret ID or label is provided, it retrieves the secret and grants it to the relation.

        Raises:
            NoSuchSecretError
            SecretRemovedError
        """
        if secret:
            secret.grant(relation)
            return
        secret = self.get_secret(id=secret_id, label=secret_label)
        secret.grant(relation)

    def remove_secret(self, label: str, id: str | None = None) -> None:
        """Remove the secret if it exists."""
        try:
            secret = self.get_secret(label=label, id=id)
            secret.remove_all_revisions()
        except (NoSuchSecretError, SecretNotFoundError):
            logger.warning("No such secret %s, nothing to remove", label)
            return

    # Relation related methods
    def get_relation(self, name: str, id: int) -> Relation:
        """Get the relation object by name and id.

        Returns:
            The relation object

        Raises:
            NoSuchRelationError: if the relation does not exist
        """
        relation = self.charm.model.get_relation(name, id)
        if not relation:
            raise NoSuchRelationError(f"Relation {name}:{id} not found")
        return relation

    def get_relation_by_name(self, name: str) -> Relation:
        """Get the relation object by name.

        Raises:
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        relations = self.charm.model.relations.get(name, [])
        if not relations:
            raise NoSuchRelationError(f"Relation {name} not found")
        if len(relations) > 1:
            raise MultipleRelationsFoundError(f"More than one relation found for name {name}")
        return relations[0]

    def get_relations(self, name: str) -> List[Relation]:
        """Get all relation objects with the given name.

        Returns:
            A list of relation objects, the list is empty if no relations are found
        """
        relations = self.charm.model.relations.get(name, [])
        if not relations:
            logger.warning("No relations found for %s", name)
        return relations

    def get_active_relation(self, name: str, id: int) -> Relation | None:
        """Get the active relation object by name and id."""
        try:
            relation = self.get_relation(name, id)
        except NoSuchRelationError:
            return None
        if not relation.active:
            logger.warning("Relation %s:%d is not active", name, id)
            return None
        return relation

    def get_active_relations(self, name: str, id: int | None = None) -> List[Relation]:
        """Get all relations with the given name that are active."""
        relations = self.get_relations(name) if not id else [self.get_relation(name, id)]
        return [relation for relation in relations if relation.active]

    def relation_exists(self, name: str) -> bool:
        """Check if there are any relations with the given name."""
        return self.get_relations(name) != []

    def _read_relation_data(
        self,
        entity: Unit | Application,
        id: int | None = None,
        name: str | None = None,
        relation: Relation | None = None,
    ) -> RelationDataContent | dict[str, str]:
        if not relation:
            if not name:
                raise ValueError("Either relation or relation_name must be provided")
            relation = self.get_relation(name, id) if id else self.get_relation_by_name(name)
        return relation.data.get(entity, {})

    def get_app_relation_data(
        self,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> RelationDataContent | dict[str, str]:
        """Get relation data from the caller's application databag.

        Either relation or relation_name must be provided.

        Returns:
            The relation data as a dict

        Raises:
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        return self._read_relation_data(
            name=name,
            entity=self.charm.model.app,
            id=id,
            relation=relation,
        )

    def get_remote_app_relation_data(
        self,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> RelationDataContent | dict[str, str]:
        """Get relation data from the remote application databag.

        Either relation or relation_name must be provided.

        Returns:
            The relation data as a dict

        Raises:
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        if not relation and not name:
            raise ValueError("Either relation or relation_name must be provided")
        relation = (
            (self.get_relation(name, id) if id else self.get_relation_by_name(name))
            if not relation and name
            else relation
        )
        if not relation:
            raise NoSuchRelationError(f"Relation {name}:{id} not found")
        if not relation.app:
            raise NoRemoteAppError(f"Relation {name}:{id} has no remote application yet")
        return relation.data.get(relation.app, {})

    def get_unit_relation_data(
        self,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> RelationDataContent | dict[str, str]:
        """Get relation data from the caller's unit databag.

        Raises:
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        return self._read_relation_data(
            name=name,
            entity=self.charm.model.unit,
            id=id,
            relation=relation,
        )

    def get_remote_unit_relation_data(
        self,
        unit: Unit,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> RelationDataContent | dict[str, str]:
        """Get relation data from the remote unit databag."""
        return self._read_relation_data(
            name=name,
            entity=unit,
            id=id,
            relation=relation,
        )

    def get_remote_units_relation_data(
        self,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> List[RelationDataContent | dict[str, str]]:
        """Get relation data from the remote units databags.

        Raises:
            NoSuchRelationError
            MultipleRelationsFoundError
            ValueError
        """
        if not relation:
            if not name:
                raise ValueError("Either relation or relation_name must be provided")
            relation = self.get_relation(name, id) if id else self.get_relation_by_name(name)
        return [relation.data.get(unit, {}) for unit in relation.units]

    def _set_relation_data(
        self,
        data: dict[str, str],
        entity: Unit | Application,
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> None:
        if not relation:
            if not name:
                raise ValueError("Either relation or relation_name must be provided")
            relation = self.get_relation(name, id) if id else self.get_relation_by_name(name)

        if not all(isinstance(value, str) for value in chain(data.values(), data.keys())):
            raise InvalidRelationDataError("Invalid relation data")
        try:
            logger.info("Setting relation data for %s:%d", name, id or relation.id)
            relation.data[entity].update(data)
        except RelationDataError as e:
            logger.error(
                "Error setting relation data for %s:%d: %s",
                name,
                id or relation.id,
                e,
            )
            raise InvalidRelationDataError(e) from e

    def set_app_relation_data(
        self,
        data: dict[str, str],
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> None:
        """Set relation data in the caller's application databag.

        Raises:
            NotLeaderError
            InvalidRelationDataError
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        if not self.charm.model.unit.is_leader():
            raise NotLeaderError("Action not allowed for non-leader units")
        self._set_relation_data(
            data=data,
            name=name,
            id=id,
            relation=relation,
            entity=self.charm.model.app,
        )

    def set_unit_relation_data(
        self,
        data: dict[str, str],
        name: str | None = None,
        id: int | None = None,
        relation: Relation | None = None,
    ) -> None:
        """Set relation data in the caller's unit databag.

        Raises:
            InvalidRelationDataError
            NoSuchRelationError
            MultipleRelationsFoundError
        """
        self._set_relation_data(
            data=data,
            name=name,
            id=id,
            relation=relation,
            entity=self.charm.model.unit,
        )

    # Charm config related methods
    def get_string_config(self, key: str) -> str:
        """Get a string config value."""
        return cast(str, self.charm.model.config.get(key)) or ""

    def get_int_config(self, key: str) -> int | None:
        """Get an integer config value."""
        return cast(int, self.charm.model.config.get(key))

    def get_bool_config(self, key: str) -> bool | None:
        """Get a boolean config value."""
        return cast(bool, self.charm.model.config.get(key))

    # Other functions
    def get_storage_location(self, storage_name: str) -> Path:
        """Get the storage location."""
        storages = self.charm.model.storages
        if not storages[storage_name]:
            raise NoSuchStorageError(f"Storage {storage_name} not found")
        try:
            return storages[storage_name][0].location
        except ModelError as e:
            # This shouldn't happen, but it does. Possibly a bug in Juju.
            # The storage "exists" on the model, but it hasn't been provisioned
            # yet, so when we try to access the location, it raises an error.
            logger.warning("Error getting storage location for %s: %s", storage_name, e)
            raise TransientJujuError(f"`{storage_name}` has not been provisioned yet") from e

    def get_binding(
        self,
        relation_name: str | None = None,
        relation: Relation | None = None,
        relation_id: int | None = None,
    ) -> Binding | None:
        """Get the binding for the given relation."""
        if not relation:
            if not relation_name:
                raise ValueError("Either relation or relation_name must be provided")
            try:
                relation = (
                    self.get_relation(relation_name, relation_id)
                    if relation_id
                    else self.get_relation_by_name(relation_name)
                )
            except NoSuchRelationError:
                return None
        return self.charm.model.get_binding(relation)

    def get_egress_subnets(
        self,
        relation_name: str,
        relation_id: int | None = None,
        relation: Relation | None = None,
    ) -> List[str]:
        """Get the list of egress subnets for the given relation.

        This returns how units on the relation will see the charm connecting from.
        For example ['10.0.0.1/32', '10.1.1.1/32']
        """
        binding = self.get_binding(
            relation_name=relation_name, relation_id=relation_id, relation=relation
        )
        if not binding:
            return []
        egress_subnets = [str(subnet) for subnet in binding.network.egress_subnets]
        if binding.network.interfaces:
            egress_subnets.append(str(binding.network.interfaces[0].subnet))
        return egress_subnets

    def get_ingress_address(
        self,
        relation_name: str | None = None,
        relation: Relation | None = None,
        relation_id: int | None = None,
    ) -> str | None:
        """Get the ingress address for the given relation."""
        binding = self.get_binding(
            relation_name=relation_name, relation_id=relation_id, relation=relation
        )
        if not binding or not binding.network.ingress_address:
            return None
        return str(binding.network.ingress_address)

    def get_bind_address(
        self,
        relation_name: str,
        relation_id: int | None = None,
        relation: Relation | None = None,
    ) -> str | None:
        """Get the bind address for the given relation."""
        binding = self.get_binding(
            relation_name=relation_name, relation_id=relation_id, relation=relation
        )
        if not binding or not binding.network.bind_address:
            return None
        return str(binding.network.bind_address)

    @property
    def model_name(self) -> str:
        """Get the model name."""
        return self.charm.model.name

    @property
    def app_name(self) -> str:
        """Get the application name."""
        return self.charm.app.name

    @property
    def unit_name(self) -> str:
        """Get the unit name."""
        return self.charm.unit.name

    @property
    def model_storage_names(self) -> List[str]:
        """Get the model storage names."""
        return list(self.charm.model.storages.keys())

    @property
    def is_leader(self) -> bool:
        """Check if the unit is leader."""
        return self.charm.unit.is_leader()

    @property
    def planned_units_for_app(self) -> int:
        """Return the number of planned units for the application."""
        return self.charm.app.planned_units()
