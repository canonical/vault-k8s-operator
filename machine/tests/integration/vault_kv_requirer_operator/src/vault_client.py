# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import hvac

logger = logging.getLogger(__name__)


class VaultClient:
    def __init__(
        self, url: str, ca_certificate: str, approle_role_id: str, approle_secret_id: str
    ):
        self._client = hvac.Client(url=url, verify=ca_certificate)
        self._approle_login(approle_role_id, approle_secret_id)

    def _approle_login(self, role_id: str, secret_id: str) -> None:
        """Login to Vault using AppRole."""
        login_response = self._client.auth.approle.login(
            role_id=role_id, secret_id=secret_id, use_token=False
        )
        self._client.token = login_response["auth"]["client_token"]

    def create_secret_in_kv(self, path: str, mount: str, key: str, value: str) -> None:
        """Create a secret in Vault KV."""
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path, secret={"data": {key: value}}, mount_point=mount
        )
        logger.info("Secret %s created in mount %s", key, mount)

    def get_secret_in_kv(self, path: str, mount: str) -> dict:
        """Get a secret from Vault KV."""
        response = self._client.secrets.kv.v2.read_secret(path=path, mount_point=mount)
        return response["data"]["data"]["data"]
