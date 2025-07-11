# Integrate with COS (K8s)

In this guide, we will cover how-to integrate Vault K8s with Canonical Observability Stack (COS) for metrics, logs, and dashboards.

## Pre-requisites

* Juju >= 3.4

## 1. Deploy COS Lite

Create a model for observability:

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
juju offer cos.grafana:grafana-dashboard
```

## 2. Integrate with COS

Switch to the model in which Vault is deployed:

```
juju switch <vault model>
```

Deploy Grafana Agent:

```
juju deploy grafana-agent-k8s
```

Integrate Vault K8s with Grafana Agent:

```
juju integrate vault-k8s:logging grafana-agent-k8s
juju integrate vault-k8s:metrics-endpoint grafana-agent-k8s
juju integrate vault-k8s:grafana-dashboard grafana-agent-k8s
```

Consume the COS offers:

```
juju consume cos.prometheus
juju consume cos.loki
juju consume cos.grafana
```

Integrate Grafana Agent with COS:

```
juju integrate prometheus:receive-remote-write grafana-agent-k8s:send-remote-write
juju integrate loki:logging grafana-agent-k8s:logging-consumer
juju integrate grafana:grafana-dashboard grafana-agent-k8s:grafana-dashboards-provider
``` 

## 3. Access the Vault dashboard

Switch to the cos model:

```
juju switch cos
```

Retrieve the Grafana admin password:
```
juju run grafana/leader get-admin-password
```

Log in Grafana, and select the Vault dashboard.

```{image} ../images/cos.png
:alt: Canonical Observability Stack
:align: center
```
