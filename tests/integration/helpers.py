#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from juju.unit import Unit
from lightkube import Client as KubernetesClient
from lightkube.resources.core_v1 import Pod


def crash_pod(name: str, namespace: str) -> None:
    """Simulates a pod crash by deleting the pod."""
    k8s = KubernetesClient()
    k8s.delete(Pod, name=name, namespace=namespace)


async def get_leader_unit(model, application_name: str) -> Unit:
    """Returns the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")
