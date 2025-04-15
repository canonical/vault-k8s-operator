# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.vault.name
}

output "requires" {
  value = {
    vault-autounseal-requires = "vault-autounseal-requires"
    ingress                   = "ingress"
    ingress-per-unit          = "ingress-per-unit"
    tls-certificates-access   = "tls-certificates-access"
    tls-certificates-pki      = "tls-certificates-pki"
    logging                   = "logging"
    s3-parameters             = "s3-parameters"
    tracing                   = "tracing"
  }
}

output "provides" {
  value = {
    vault-autounseal-provides = "vault-autounseal-provides"
    vault-kv                  = "vault-kv"
    vault-pki                 = "vault-pki"
    metrics-endpoint          = "metrics-endpoint"
    send-ca-cert              = "send-ca-cert"
    grafana-dashboard         = "grafana-dashboard"
  }
}
