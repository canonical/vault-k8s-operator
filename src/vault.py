#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Contains all the specificities to communicate with Vault through its API."""

import logging
from time import sleep, time
from typing import List, Tuple

import hvac  # type: ignore[import]
import requests

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Exception raised for Vault errors."""

    pass


class Vault:
    """Class to interact with Vault through its API."""

    def __init__(self, url: str):
        self._client = hvac.Client(url=url)

    def is_ready(self) -> bool:
        """Returns whether Vault is ready for interaction."""
        if not self._client.sys.is_initialized():
            return False
        if self._client.sys.is_sealed():
            return False
        health_status = self._client.sys.read_health_status()
        if health_status.status_code != 200:
            return False
        return True

    def initialize(
        self, secret_shares: int = 1, secret_threshold: int = 1
    ) -> Tuple[str, List[str]]:
        """Initialize Vault.

        Returns:
            A tuple containing the root token and the unseal keys.
        """
        initialize_response = self._client.sys.initialize(
            secret_shares=secret_shares, secret_threshold=secret_threshold
        )
        return initialize_response["root_token"], initialize_response["keys"]

    def is_sealed(self) -> bool:
        """Returns whether Vault is sealed."""
        return self._client.sys.is_sealed()

    def unseal(self, unseal_keys: List[str]) -> None:
        """Unseal Vault."""
        for unseal_key in unseal_keys:
            self._client.sys.submit_unseal_key(unseal_key)

    def wait_to_be_ready(self, timeout: int = 30):
        """Wait for vault to be ready."""
        start_time = time()
        while time() - start_time < timeout:
            if self.is_ready():
                return
            sleep(2)
        raise TimeoutError("Timed out waiting for vault to be ready")

    def wait_for_api_available(self, timeout: int = 30) -> None:
        """Wait for vault to be available."""
        start_time = time()
        while time() - start_time < timeout:
            if self.is_api_available():
                return
            sleep(2)
        raise TimeoutError("Timed out waiting for vault to be available")

    def is_api_available(self) -> bool:
        """Returns whether Vault is available."""
        try:
            self._client.sys.read_health_status()
        except requests.exceptions.ConnectionError:
            return False
        return True

    def set_token(self, token: str) -> None:
        """Sets the Vault token for authentication."""
        self._client.token = token
