# Integrate with COS (Machine)

In this guide, we will cover how-to integrate Vault with Canonical Observability Stack (COS) for metrics and logs.

## Pre-requisites

* Juju >= 3.4

## 1. Deploy COS Lite

Create a Kubernetes model for observability:

```
juju add-model cos
```

Deploy cos lite and wait for all applications to be in active status:

```
juju deploy cos-lite --trust
```

Create offers for integrating with COS:
```
juju offer cos.prometheus:receive-remote-write
juju offer cos.loki:logging
```

## 2. Integrate with COS

Switch to the machine model in which Vault is deployed:

```
juju switch <vault model>
```

Deploy Grafana Agent:

```
juju deploy grafana-agent
```

Integrate Vault with Grafana Agent:

```
juju integrate vault:cos-agent grafana-agent:cos-agent
```

Consume the COS offers:

```
juju consume <k8s controller>:admin/cos.prometheus
juju consume <k8s controller>:admin/cos.loki
```

Integrate Grafana Agent with COS:

```
juju integrate prometheus:receive-remote-write grafana-agent:send-remote-write
juju integrate loki:logging grafana-agent:logging-consumer
``` 

## 3. Access Vault metrics and logs

Switch to the cos model:

```
juju switch cos
```

Retrieve the Grafana admin password:
```
juju run grafana/leader get-admin-password
```

Log in Grafana, and access metrics and logs.
