ui      = true
storage "raft" {
  path= "/var/snap/vault/common/raft"
  node_id = "whatever-vault/0"
  }
log_level = "info"
listener "tcp" {
  telemetry {
    unauthenticated_metrics_access = true
  }
  address       = "[::]:8200"
  tls_cert_file = "/var/snap/vault/common/certs/cert.pem"
  tls_key_file  = "/var/snap/vault/common/certs/key.pem"
}
default_lease_ttl = "168h"
max_lease_ttl     = "720h"
disable_mlock     = true
cluster_addr      = "https://1.2.1.2:8201"
api_addr          = "https://1.2.1.2:8200"
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}
