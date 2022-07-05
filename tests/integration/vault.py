#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from typing import Optional

import hvac  # type: ignore[import]

logger = logging.getLogger(__name__)


class Vault:
    """Class to interact with Vault through its API."""

    def __init__(self, url: str):
        self._client = hvac.Client(url=url)

    @property
    def token(self) -> Optional[str]:
        """Returns Vault's token.

        Returns:
            str: Vault token.
        """
        return self._client.token

    def set_token(self, token: str) -> None:
        """Sets the Vault token.

        Args:
            token (str): Vault token

        Returns:
            None
        """
        self._client.token = token

    def initialize(self) -> tuple:
        """Initializes Vault and returns root token and unseal key.

        Returns:
            str: Unseal key
            str: Root Token
        """
        result = self._client.sys.initialize(secret_shares=1, secret_threshold=1)
        logger.info("Initialized Vault")
        return result["keys"][0], result["root_token"]

    def unseal(self, unseal_key: str) -> None:
        """Unseals Vault.

        Returns:
            None
        """
        self._client.sys.submit_unseal_key(unseal_key)
        logger.info("Unsealed Vault")

    def generate_token(self, ttl: str) -> str:
        """Generates Vault token.

        Args:
            ttl (str): Time to Live

        Returns:
            str: token
        """
        response = self._client.auth.token.create(ttl=ttl)
        logger.info("Generated token for charm")
        return response["auth"]["client_token"]
