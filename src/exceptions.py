# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exceptions used within the Vault charm."""


class VaultCertsError(Exception):
    """Exception raised when a vault certificate is not found."""

    def __init__(self, message: str = "Could not retrieve vault certificates from local storage"):
        self.message = message
        super().__init__(self.message)


class PeerSecretError(Exception):
    """Exception raised when a peer secret is not found."""

    def __init__(
        self, secret_name: str, message: str = "Could not retrieve secret from peer relation"
    ):
        self.secret_name = secret_name
        self.message = message
        super().__init__(self.message)
