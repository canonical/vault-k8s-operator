ui      = true
storage "raft" {
  path= "/vault/raft"
  node_id = "whatever-vault-k8s/0"

  }
listener "tcp" {
  telemetry {
    unauthenticated_metrics_access = true
  }
  address       = "[::]:8200"
  tls_cert_file = "/vault/certs/cert.pem"
  tls_key_file  = "/vault/certs/key.pem"
}
default_lease_ttl = "168h"
max_lease_ttl     = "720h"
disable_mlock     = true
cluster_addr      = "https://myhostname:8201"
api_addr          = "https://myhostname:8200"
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}
