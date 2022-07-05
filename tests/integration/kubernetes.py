#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from typing import Optional

from lightkube import Client
from lightkube.resources.core_v1 import Service

logger = logging.getLogger(__name__)


class Kubernetes:
    """Class to interact with Vault through its API."""

    def __init__(self, namespace: str):
        self.client = Client()
        self.namespace = namespace

    def get_load_balancer_address(self, service_name: str) -> Optional[str]:
        """Returns the services' load balancer IP address or hostname.

        Args:
            service_name: Kubernetes service Name

        Returns:
            str: Load balancer IP address or hostname.
        """
        service = self.client.get(Service, service_name, namespace=self.namespace)
        ingresses = service.status.loadBalancer.ingress  # type: ignore[attr-defined]
        if ingresses:
            ip = ingresses[0].ip
            hostname = ingresses[0].hostname
            if hostname:
                logger.info(f"Found Loadbalancer address: {hostname}")
                return hostname
            else:
                logger.info(f"Found Loadbalancer address: {ip}")
                return ip
        else:
            logger.info(f"Ingress not yet available for {service_name}")
            return None
