#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import ops.testing as testing
import pytest
from scenario.errors import UncaughtCharmError

from fixtures import VaultCharmFixtures


class TestCharmLogrotate(VaultCharmFixtures):
    @pytest.mark.parametrize("frequency", ["daily", "weekly", "monthly"])
    def test_given_valid_logrotate_frequency_when_configure_then_logrotate_conf_is_written(
        self, frequency: str
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": frequency},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_logrotate_path.write_text.assert_called_once()

    @pytest.mark.parametrize("frequency", ["daily", "weekly", "monthly"])
    def test_given_valid_logrotate_frequency_when_configure_then_logrotate_conf_contains_frequency(
        self, frequency: str
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": frequency},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        written_content = self.mock_logrotate_path.write_text.call_args[0][0]
        assert frequency in written_content

    def test_given_valid_logrotate_frequency_when_configure_then_logrotate_conf_contains_default_rotate_count(
        self,
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": "daily"},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        written_content = self.mock_logrotate_path.write_text.call_args[0][0]
        assert "rotate 7" in written_content

    def test_given_valid_logrotate_frequency_when_configure_then_logrotate_conf_contains_default_maxsize(
        self,
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": "daily"},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        written_content = self.mock_logrotate_path.write_text.call_args[0][0]
        assert "maxsize 10M" in written_content

    def test_given_valid_logrotate_frequency_when_configure_then_logrotate_conf_targets_syslog(
        self,
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": "daily"},
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        written_content = self.mock_logrotate_path.write_text.call_args[0][0]
        assert "/var/log/syslog" in written_content

    def test_given_invalid_logrotate_frequency_when_configure_then_charm_error_is_raised(
        self,
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": "hourly"},
        )

        with pytest.raises(UncaughtCharmError):
            self.ctx.run(self.ctx.on.config_changed(), state_in)

    def test_given_invalid_logrotate_frequency_when_configure_then_logrotate_conf_is_not_written(
        self,
    ):
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            config={"logrotate_frequency": "hourly"},
        )

        with pytest.raises(UncaughtCharmError):
            self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_logrotate_path.write_text.assert_not_called()
