#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine abstraction for the Vault charm."""

import logging
import os
import shutil
import signal
from pathlib import Path
from typing import TextIO

import psutil
from charms.operator_libs_linux.v2 import snap
from vault.vault_managers import WorkloadBase

logger = logging.getLogger(__name__)


class Machine(WorkloadBase):
    """A class to interact with a unit machine.

    This class implements the WorkloadBase interface
    that has the same method signatures as Pebble API in the Ops
    Library.
    """

    def exists(self, path: str) -> bool:
        """Check if a file exists.

        Args:
            path: The path of the file

        Returns:
            bool: Whether the file exists
        """
        return os.path.isfile(path)

    def pull(self, path: str) -> TextIO:
        """Get the content of a file.

        Args:
            path: The path of the file

        Returns:
            str: The content of the file
        """
        return open(path, "r")

    def push(self, path: str, source: str) -> None:
        """Pushes a file to the unit.

        Args:
            path: The path of the file
            source: The contents of the file to be pushed
        """
        with open(path, "w") as write_file:
            write_file.write(source)
            logger.info("Pushed file %s", path)

    def make_dir(self, path: str) -> None:
        """Create a directory."""
        Path(path).mkdir(parents=True, exist_ok=True)

    def remove_path(self, path: str, recursive: bool = False) -> None:
        """Remove a file or directory.

        Args:
            path: The absolute path of the file or directory
            recursive: Whether to remove recursively
        raises:
            ValueError: If the path is not absolute.
        """
        if not os.path.isabs(path):
            raise ValueError(f"The provided path is not absolute: {path}")
        if os.path.isdir(path) and recursive:
            shutil.rmtree(path)
            logger.debug("Recursively removed directory `%s`", path)
        elif os.path.isfile(path) or (os.path.isdir(path) and not recursive):
            os.remove(path)
            logger.debug("Removed file or directory `%s`", path)
        else:
            raise ValueError(f"Path `{path}` does not exist.")

    def send_signal(self, signal: int, process: str) -> None:
        """Send a signal to the charm.

        Args:
            signal: The signal to send
            process: The name of the process
        """
        if pid := self._find_process(process):
            os.kill(pid, signal)
            logger.info("Sent signal %s to charm", signal)

    def restart(self, process: str) -> None:
        """Restarts all services specified in the snap."""
        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[process]
        vault_snap.restart()

    def stop(self, process: str) -> None:
        """Stop a process.

        Args:
            process: The name of the process
        """
        if pid := self._find_process(process):
            os.kill(pid, signal.SIGTERM)
            logger.info("Stopped process %s", process)

    def get_service(self, process: str) -> psutil.Process | None:
        """Get a service.

        Args:
            process: The name of the process

        Returns:
            psutil.Process: The process
        """
        if pid := self._find_process(process):
            return psutil.Process(pid)
        return None

    def _find_process(self, process: str) -> int | None:
        """Find a process.

        Args:
            process: The name of the process

        Returns:
            int: The process ID
        """
        processes = list(psutil.process_iter())
        for proc in processes:
            try:
                if proc.name() == process:
                    return proc.pid
            except psutil.NoSuchProcess:
                logger.debug("Process %s exited during check", proc.pid)
                continue
        return None

    def is_accessible(self) -> bool:
        """Return True for the machine workload.

        Unlike a workload which runs in a container, the machine workload
        is always accessible, since it runs on the host machine.

        Returns:
            True
        """
        return True
