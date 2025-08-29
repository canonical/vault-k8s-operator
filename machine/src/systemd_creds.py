#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Generic wrapper for Systemd Credentials.

This module provides a high-level interface for managing systemd credentials,
including encryption and decryption.

This module is designed to be used as a drop-in replacement for direct calls to
systemd-creds, providing a more Pythonic interface and handling common tasks.

"""

import logging
import subprocess
from pathlib import Path

ENCRYPTED_CREDENTIAL_STORE = Path("/etc/credstore.encrypted/")

logger = logging.getLogger(__name__)


class SystemdCreds:
    """A class to manage systemd encrypted credentials."""

    @staticmethod
    def decrypt(name: str) -> str:
        """Decrypt a token from the systemd encrypted credential store."""
        path = ENCRYPTED_CREDENTIAL_STORE / name
        decrypted_token = subprocess.run(
            ["systemd-creds", "decrypt", f"--name={name}", path],
            capture_output=True,
            text=True,
        )
        if decrypted_token.returncode != 0:
            logger.error(
                "Failed to decrypt credential %s. stderr: %s", name, decrypted_token.stderr.strip()
            )
            raise RuntimeError("Token decryption failed")
        return decrypted_token.stdout.strip()

    @staticmethod
    def encrypt(name: str, value: str) -> None:
        """Encrypt a token and store it in the systemd encrypted credential store.

        This token will then be loadable by name using
        ``LoadCredentialEncrypted`` in a unit file.
        """
        path = ENCRYPTED_CREDENTIAL_STORE / name
        subprocess.run(
            [
                "systemd-creds",
                "encrypt",
                f"--name={name}",  # Credential name
                "-",  # Take input from stdin (instead of a file)
                path,  # Encrypted credential output location
            ],
            input=value,
            text=True,
            check=True,
        )

    @staticmethod
    def encrypt_if_changed(name: str, value: str) -> None:
        """Encrypt a token if it has changed since the last time it was written."""
        path = ENCRYPTED_CREDENTIAL_STORE / name
        if path.exists():
            current_value = SystemdCreds.decrypt(name)
            if current_value == value:
                logger.debug("Token %s has not changed, skipping encryption.", name)
                return
        SystemdCreds.encrypt(name, value)
        logger.debug("Token %s has been encrypted and stored.", name)

    @staticmethod
    def is_credentials_supported():
        """Detect if the current setup supports systemd-creds."""
        try:
            subprocess.run(["systemd-creds", "setup"], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def reload_daemon() -> None:
        """Reload the systemd daemon to apply changes."""
        subprocess.run(["systemctl", "daemon-reload"], check=True)
