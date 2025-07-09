from datetime import datetime, timedelta
from typing import cast
from unittest.mock import Mock

import pytest
from ops.model import ModelError, SecretNotFoundError
from vault.juju_facade import (
    InvalidRelationDataError,
    JujuFacade,
    MultipleRelationsFoundError,
    NoSuchRelationError,
    NoSuchSecretError,
    NoSuchStorageError,
    NotLeaderError,
    SecretRemovedError,
    TransientJujuError,
)


class TestJujuFacade:
    @pytest.fixture(autouse=True)
    def setup(self):
        charm = Mock()
        charm.model = Mock(storages={"storage": []})
        charm.app = Mock()
        charm.unit = Mock()
        self.facade = JujuFacade(charm)

    # Tests for Secret methods

    def test_given_no_label_or_id_when_get_secret_then_raises_value_error(self):
        with pytest.raises(ValueError):
            self.facade.get_secret()

    def test_given_model_error_when_get_secret_then_raises_transient_error(self):
        self.facade.charm.model.get_secret = Mock(side_effect=ModelError())

        with pytest.raises(TransientJujuError):
            self.facade.get_secret("test-secret")

    def test_given_model_error_when_secret_exists_then_raises_transient_error(self):
        self.facade.charm.model.get_secret = Mock(side_effect=ModelError())

        with pytest.raises(TransientJujuError):
            self.facade.secret_exists("test-secret")

    def test_given_secret_not_found_when_secret_exists_then_returns_false(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())

        assert not self.facade.secret_exists("test-secret")

    def test_given_secret_exists_with_exact_fields_when_secret_exists_with_fields_then_returns_true(
        self,
    ):
        secret = Mock()
        self.facade.charm.model.get_secret = Mock(return_value=secret)
        secret.get_content = Mock(return_value={"key": "value"})

        assert self.facade.secret_exists_with_fields(("key",), "test-secret")

    def test_given_secret_exists_with_missing_fields_when_secret_exists_with_fields_then_returns_false(
        self,
    ):
        secret = Mock()
        self.facade.charm.model.get_secret = Mock(return_value=secret)
        secret.get_content = Mock(return_value={"key": "value"})

        assert not self.facade.secret_exists_with_fields(("key1",), "test-secret")

    def test_given_secret_not_found_when_secret_exists_with_fields_then_returns_false(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())

        assert not self.facade.secret_exists_with_fields(("key",), "test-secret")

    def test_given_secret_removed_when_get_secret_content_values_then_raises_no_such_secret(self):
        secret = Mock()
        self.facade.charm.model.get_secret = Mock(return_value=secret)
        secret.get_content = Mock(side_effect=SecretNotFoundError())

        with pytest.raises(SecretRemovedError):
            self.facade.get_current_secret_content("test-secret")

    def test_given_model_error_when_get_secret_content_values_then_raises_transient_error(self):
        self.facade.charm.model.get_secret = Mock(side_effect=ModelError())

        with pytest.raises(TransientJujuError):
            self.facade.get_current_secret_content("test-secret")

    def test_given_secret_when_get_latest_secret_content_then_secret_is_refreshed(self):
        secret = Mock()
        secret.get_content = Mock(return_value={"key": "value"})
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        assert self.facade.get_latest_secret_content("test-secret") == {"key": "value"}
        secret.get_content.assert_called_with(refresh=True)

    def test_given_secret_when_get_secret_content_values_then_returns_specified_values_only(self):
        secret = Mock()
        secret.get_content = Mock(
            return_value={"key1": "value1", "key2": "value2", "key3": "value3"}
        )
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        assert self.facade.get_secret_content_values("key1", "key3", label="test-secret") == (
            "value1",
            "value3",
        )

    def test_given_secret_exists_when_set_app_secret_content_with_same_content_then_skips_update(
        self,
    ):
        secret = Mock()
        content = {"key": "value"}
        secret.get_content = Mock(return_value=content)
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        result = self.facade.set_app_secret_content(content, "test-label")

        secret.set_content.assert_not_called()
        assert result == secret

    def test_given_secret_not_exists_when_set_app_secret_content_then_creates_new_secret(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())
        content = {"key": "value"}
        new_secret = Mock()
        self.facade.charm.app.add_secret = Mock(return_value=new_secret)

        result = self.facade.set_app_secret_content(content, "test-label")

        self.facade.charm.app.add_secret.assert_called_once_with(
            content, label="test-label", description=None
        )
        assert result == new_secret

    def test_given_secret_exists_when_set_unit_secret_content_with_same_content_then_skips_update(
        self,
    ):
        secret = Mock()
        content = {"key": "value"}
        secret.get_content = Mock(return_value=content)
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        result = self.facade.set_unit_secret_content(content, "test-label")
        secret.set_content.assert_not_called()
        assert result == secret

    def test_given_secret_not_exists_when_set_unit_secret_content_then_creates_new_secret(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())
        content = {"key": "value"}
        new_secret = Mock()
        self.facade.charm.unit.add_secret = Mock(return_value=new_secret)

        result = self.facade.set_unit_secret_content(content, "test-label")
        assert result == new_secret

    def test_given_secret_when_set_secret_label_then_secret_label_is_updated(self):
        secret = Mock()
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        self.facade.set_secret_label("new-label", "test-label")
        secret.set_info.assert_called_with(label="new-label")

    def test_given_secret_not_found_when_set_secret_label_then_raises_no_such_secret(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())

        with pytest.raises(NoSuchSecretError):
            self.facade.set_secret_label("new-label", "test-label")

    def test_given_model_error_when_set_secret_label_then_raises_transient_error(self):
        self.facade.charm.model.get_secret = Mock(side_effect=ModelError())

        with pytest.raises(TransientJujuError):
            self.facade.set_secret_label("new-label", "test-label")

    def test_given_secret_when_set_secret_expiry_then_secret_expiry_is_updated(self):
        secret = Mock()
        self.facade.charm.model.get_secret = Mock(return_value=secret)

        expiry = datetime.now() + timedelta(days=1)
        self.facade.set_secret_expiry(expiry, "test-label")

        actual_expiry = secret.set_info.call_args[1]["expire"]
        assert actual_expiry.timestamp() == expiry.timestamp()

    def test_given_secret_not_found_when_set_secret_expiry_then_raises_no_such_secret(self):
        self.facade.charm.model.get_secret = Mock(side_effect=SecretNotFoundError())

        with pytest.raises(NoSuchSecretError):
            self.facade.set_secret_expiry(datetime.now() + timedelta(days=1), "test-label")

    def test_given_model_error_when_set_secret_expiry_then_raises_transient_error(self):
        self.facade.charm.model.get_secret = Mock(side_effect=ModelError())

        with pytest.raises(TransientJujuError):
            self.facade.set_secret_expiry(datetime.now() + timedelta(days=1), "test-label")

    # Tests for Relation methods

    def test_given_relation_not_found_when_get_relation_then_raises_no_such_relation(self):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.get_relation("test-relation", 1)

    def test_given_relation_not_found_when_get_app_relation_data_then_raises_no_such_relation(
        self,
    ):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.get_app_relation_data("test-relation", 1)

    def test_given_relation_not_found_when_get_remote_app_relation_data_then_raises_no_such_relation(
        self,
    ):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.get_remote_app_relation_data("test-relation", 1)

    def test_given_relation_not_found_when_get_unit_relation_data_then_raises_no_such_relation(
        self,
    ):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.get_unit_relation_data("test-relation", 1)

    def test_given_relation_when_get_remote_units_relation_data_then_returns_list_of_relation_data(
        self,
    ):
        relation = Mock()
        relation.units = ["unit-1", "unit-2"]
        relation.data = {"unit-1": {"key": "value1"}, "unit-2": {"key": "value2"}}
        self.facade.charm.model.get_relation = Mock(return_value=relation)

        assert self.facade.get_remote_units_relation_data("test-relation", 1) == [
            {"key": "value1"},
            {"key": "value2"},
        ]

    def test_given_not_leader_when_set_app_relation_data_then_raises_not_leader(self):
        self.facade.charm.model.unit.is_leader = Mock(return_value=False)

        with pytest.raises(NotLeaderError):
            self.facade.set_app_relation_data({"key": "value"}, "test-relation", 1)

    def test_given_relation_not_found_when_set_app_relation_data_then_raises_no_such_relation(
        self,
    ):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.set_app_relation_data({"key": "value"}, "test-relation", 1)

    def test_given_relation_not_found_when_set_unit_relation_data_then_raises_no_such_relation(
        self,
    ):
        self.facade.charm.model.get_relation = Mock(return_value=None)

        with pytest.raises(NoSuchRelationError):
            self.facade.set_unit_relation_data({"key": "value"}, "test-relation", 1)

    def test_given_invalid_data_when_set_relation_data_then_raises_invalid_data(self):
        relation = Mock()
        self.facade.get_relation = Mock(return_value=relation)

        data = {"key": 123}  # int value
        with pytest.raises(InvalidRelationDataError):
            self.facade.set_app_relation_data(cast(dict[str, str], data), "test-relation", 1)

    def test_given_no_relations_when_get_relation_by_name_then_raises_no_such_relation(self):
        charm = Mock()
        charm.model = Mock(relations={})
        self.facade.charm = charm

        with pytest.raises(NoSuchRelationError):
            self.facade.get_relation_by_name("test-relation")

    def test_given_multiple_relations_with_relation_name_when_get_relation_by_name_then_raises_multiple_relations_found(
        self,
    ):
        relation_1 = Mock()
        relation_2 = Mock()
        charm = Mock()
        charm.model = Mock(relations={"test-relation": [relation_1, relation_2]})
        self.facade.charm = charm

        with pytest.raises(MultipleRelationsFoundError):
            self.facade.get_relation_by_name("test-relation")

    def test_given_multiple_relations_when_get_active_relations_then_returns_only_active_relations(
        self,
    ):
        relation_1 = Mock(active=True)
        relation_2 = Mock(active=False)
        charm = Mock()
        charm.model = Mock(relations={"test-relation": [relation_1, relation_2]})
        self.facade.charm = charm

        assert self.facade.get_active_relations("test-relation") == [relation_1]

    def test_given_relation_and_relation_name_parameters_missing_when_get_relation_data_then_raises_value_error(
        self,
    ):
        with pytest.raises(ValueError):
            self.facade.get_app_relation_data(id=1)
        with pytest.raises(ValueError):
            self.facade.get_unit_relation_data(id=1)

    def test_given_relation_and_relation_name_parameters_missing_when_set_relation_data_then_raises_value_error(
        self,
    ):
        with pytest.raises(ValueError):
            self.facade.set_app_relation_data(data={"key": "value"}, id=1)
        with pytest.raises(ValueError):
            self.facade.set_unit_relation_data(data={"key": "value"}, id=1)

    # Tests for Storage methods

    def test_given_storage_not_exists_when_get_storage_location_then_raises_no_such_storage(
        self,
    ):
        with pytest.raises(NoSuchStorageError):
            self.facade.get_storage_location("storage")
