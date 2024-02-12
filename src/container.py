#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Container abstraction for the Vault charm."""

from typing import TextIO

from charms.vault_k8s.v0.vault_tls import WorkloadBase
from ops import Container as OpsContainer


class Container(WorkloadBase):
    """Adapter class that wraps ops.Container into WorkloadBase."""

    def __init__(self, container: OpsContainer):
        self._container = container

    def __getattr__(self, name):
        """Delegate all unknown attributes to the container."""
        return getattr(self._container, name)

    def exists(self, path: str) -> bool:
        """Check if a file exists in the workload."""
        return self._container.exists(path=path)

    def pull(self, path: str) -> TextIO:
        """Read file from the workload."""
        return self._container.pull(path=path)

    def push(self, path: str, source: str) -> None:
        """Write file to the workload."""
        self._container.push(path=path, source=source)

    def make_dir(self, path: str) -> None:
        """Create directory in the workload."""
        self._container.make_dir(path=path)

    def remove_path(self, path: str, recursive: bool = False) -> None:
        """Remove file or directory from the workload."""
        self._container.remove_path(path=path, recursive=recursive)

    def send_signal(self, signal: int, process: str) -> None:
        """Send a signal to a process in the workload."""
        self._container.send_signal(signal, process)
