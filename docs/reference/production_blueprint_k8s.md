# Production blueprint (k8s)

This document outlines recommendations for operating Vault in a production environment.

```{image} ../images/production_blueprint_k8s.png
:alt: Production Blueprint
:align: center
```

## Infrastructure

Please follow the [Vault project reference](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture#hardware-sizing-for-vault-servers) to deploy the Vault charms on hosts of appropriate size for your deployment.

## High Availability

Vault should be deployed with a total of **5 units**.

## Observability

Vault should be integrated with Canonical Observability Stack:

- Vault should be integrated with Grafana Agent using the `cos-agent` charm relation interface.
- Grafana Agent should be integrated with COS using the `loki_push_api`, `prometheus_remote_write`, and `grafana_dashboard` charm relation interfaces.

## Storage

The Vault charm declares minimum storage sizes for its volumes. Juju will provision
at least these amounts when deploying.

```{important}
Storage declarations cannot be changed after deployment on Kubernetes.
```

The charm defines the following storage volumes:

| Storage name | Purpose                   | Minimum size |
| ------------ | ------------------------- | ------------ |
| `vault-raft` | Raft data directory       | 10G          |
| `config`     | Vault configuration files | 5M           |
| `certs`      | TLS certificates          | 5M           |
| `tmp`        | Temporary files           | 5G           |

You can provision **larger** volumes at deploy time using the `--storage` flag:

```shell
juju deploy vault-k8s vault --trust \
  --storage vault-raft=50G \
  --storage tmp=10G
```

Note that some filesystems (e.g. XFS) enforce a minimum allocation unit larger than
the declared minimums. In such cases, use the `--storage` flag to specify sizes
compatible with your filesystem.

## Backup and Restore

Vault should be integrated with an S3 provider to conduct regular backup operations.
