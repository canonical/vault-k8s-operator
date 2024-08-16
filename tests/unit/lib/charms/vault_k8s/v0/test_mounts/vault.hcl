ui      = true
storage "raft" {
  path= "/vault/raft"
  node_id = "nSBVgkn9BWGqwAuHl7gZ-vault-k8s/0"
  
  retry_join {
    leader_api_addr = "https://vault-k8s-0.thinkpad:8200"
    leader_ca_cert_file = "/vault/certs/ca.pem"
  }
  
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
cluster_addr      = "https://thinkpad:8201"
api_addr          = "https://thinkpad:8200"
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}
