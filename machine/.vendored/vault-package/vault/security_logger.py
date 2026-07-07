#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# Licensed under the Apache2.0. See LICENSE file in charm source for details.

"""Shared OWASP-style security logger utilities.

This module defines a small, dependency-free helper to emit OWASP-inspired
security events in a nested JSON structure that is easy to parse and index.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


NESTED_JSON_KEY = "owasp_event"


@dataclass
class _OWASPLogEvent:
    """OWASP-compliant log event payload."""

    datetime: str
    event: str
    level: str
    description: str
    type: str = "security"
    labels: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:  # pragma: no cover - trivial wrapper
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def to_dict(self) -> dict:
        log_event = dict(asdict(self), **self.labels)
        log_event.pop("labels", None)
        return {k: v for k, v in log_event.items() if v is not None}


class _OWASPLogger:
    """Minimal OWASP logger that nests events under NESTED_JSON_KEY."""

    def __init__(self, application: str = "vault"):
        self._application = application
        self._logger = logging.getLogger(__name__)

    def log_event(self, *, event: str, level: int, description: str, **labels: str | None) -> None:
        level_name = logging.getLevelName(level)
        event_obj = _OWASPLogEvent(
            datetime=datetime.now(timezone.utc).isoformat(),
            event=event,
            level=str(level_name),
            description=description,
            labels={"application": self._application, **{k: v for k, v in labels.items() if v is not None}},
        )
        payload = {NESTED_JSON_KEY: event_obj.to_dict()}
        self._logger.log(level, json.dumps(payload, ensure_ascii=False))


