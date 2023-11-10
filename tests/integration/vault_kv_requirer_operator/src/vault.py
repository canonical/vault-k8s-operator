# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import hvac  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class Vault:
    def __init__(
        self, url: str, ca_certificate: str, approle_role_id: str, approle_secret_id: str
    ):
        logger.info("Vault URL: %s", url)
        logger.info("Vault CA certificate: %s", ca_certificate)
        logger.info("Login information: %s, %s", approle_role_id, approle_secret_id)
        self._client = hvac.Client(url=url, verify=ca_certificate)
        self._approle_login(approle_role_id, approle_secret_id)

    def _approle_login(self, role_id: str, secret_id: str) -> None:
        self._client.auth_approle(role_id=role_id, secret_id=secret_id)

    def create_secret_in_kv(self, mount: str, key: str, value: str) -> None:
        self._client.secrets.kv.v2.create_or_update_secret(
            path=mount, secret=dict(data={key: value})
        )
        logger.info("Secret %s created in mount %s", key, mount)
