# Vault Operator (Kubernetes)

Vault is a tool for securely managing secrets used in modern computing (e.g. passwords, certificates, API keys).

The Vault Operator deploys and initializes Vault on Kubernetes, and runs in high availability mode using the Raft backend.

## Usage

### Deploy

Deploy the charm:
```bash
juju deploy vault-k8s --channel edge -n 5 --trust
```
> Note: It is advised to deploy Vault with an odd number of units

### Access Vault through Ingress

Deploy Traefik

```bash
juju deploy traefik-k8s --channel edge --trust --config external_hostname=<your hostname> 
```

Deploy Self Signed Certificates Operator

```bash
juju deploy self-signed-certificates --channel beta
```

Integrate Traefik with Self-Signed-Certificates Operator

```bash
juju integrate self-signed-certificates:certificates traefik-k8s:certificates
```

Integrate Vault with Traefik

```bash
juju integrate vault-k8s:send-ca-cert traefik-k8s:receive-ca-cert
juju integrate vault-k8s:ingress traefik-k8s:ingress
```

Get the Vault URL 

Run the `show-proxied-endpoints` action on Traefik.

```bash
juju run traefik-k8s/0 show-proxied-endpoints

# Sample Action Output
Running operation 1 with 1 task
  - task 2 on unit-traefik-k8s-0

Waiting for task 2...
proxied-endpoints: '{"vault-k8s": {"url": "https://10.0.0.4/vault-vault-k8s"}}'
```

You should now be able to access the Vault using the URL in the action output.

### Interact with Vault via CLI

Install the Vault client:

```bash
sudo snap install vault
```

Retrieve the Juju secrets list:

```bash
user@ubuntu:~$ juju secrets --format=yaml
ck0i0h3q457c7bgte4kg:
  revision: 1
  owner: vault-k8s
  label: vault-ca-certificate
  created: 2023-09-13T02:36:57Z
  updated: 2023-09-13T02:36:57Z
ck0i0krq457c7bgte4l0:
  revision: 1
  owner: vault-k8s
  label: vault-initialization
  created: 2023-09-13T02:37:10Z
  updated: 2023-09-13T02:37:10Z
cks0s1c24l7c77v23p80:
  revision: 1
  expires: 2024-09-13T02:36:10Z
  owner: self-signed-certificates
  label: ca-certificates
  created: 2023-09-13T02:36:57Z
  updated: 2023-09-13T02:36:57Z
```

Read the `vault-initialization` secret content:

```bash
user@ubuntu:~$ juju show-secret ck0i0krq457c7bgte4l0 --reveal
ck0i0krq457c7bgte4l0:
  revision: 1
  owner: vault-k8s
  created: 2023-08-28T13:33:54Z
  updated: 2023-08-28T13:33:54Z
  content:
    roottoken: hvs.Z3CuzSQno3XMuUgUcm1CmjQK
    unsealkeys: '["11bd448ccfec24db29ed5c14fdfe3d169589f5c5c6b57870e31d738aec623856"]'
```

Set the vault token for use in the client:

```bash
export VAULT_TOKEN=hvs.Z3CuzSQno3XMuUgUcm1CmjQK
```

Read the Self Signed Certificates operator's `ca-certificates` secret content:

```bash
user@ubuntu:~$ juju show-secret cks0s1c24l7c77v23p80 --reveal
ck0i0h3q457c7bgte4kg:
  revision: 1
  owner: self-signed-certificates
  label: ca-certificates
  created: 2023-09-13T02:36:57Z
  updated: 2023-09-13T02:36:57Z
  content:
    ca-certificate: |
      -----BEGIN CERTIFICATE-----
      MIIDPTCCAiWgAwIBAgIUGLlWWWj9My3coKtn/EAgequ4rlswDQYJKoZIhvcNAQEL
      BQAwLDELMAkGA1UEBhMCVVMxHTAbBgNVBAMMFFZhdWx0IHNlbGYgc2lnbmVkIENB
      MB4XDTIzMDkxMzAyMzY1MloXDTI0MDkxMjAyMzY1MlowLDELMAkGA1UEBhMCVVMx
      HTAbBgNVBAMMFFZhdWx0IHNlbGYgc2lnbmVkIENBMIIBIjANBgkqhkiG9w0BAQEF
      AAOCAQ8AMIIBCgKCAQEA3zg2cmScuUV+EFKh4gOE6xxeaur6QEvfb1vFKLjTYRst
      iBbM5/BZE6noYwOIeyir2LgLeoLNr1tCc9EYhDJRNdCYPWUXVDZR4vD7kfZG7CUH
      8yXiQ18Q/7tYnJ63Ic3tE2VLf36Rwj6Wr9b9YrZzeqm2zQDvKUelZzsNh/UOCqzi
      Nd6PEZUQq6d7ucTqbEeOxO3UISTZjyQzx6kPsh3w0AQ4cT2kEtxT6Pg7c3bnbzwd
      TN3MOt0pVyY+2Mb6+Ep6cbB6qrluuOLfXNMBarQersddrJmhGfxq72dxIJ70uE8P
      RiyHH9+HqIoFSk5/e5Cc+VUlKnoNNbocYKh90oVcpQIDAQABo1cwVTAfBgNVHQ4E
      GAQWBBQ1EOm+fKnVxnNF1FztMjlS8LNUPDAhBgNVHSMEGjAYgBYEFDUQ6b58qdXG
      c0XUXO0yOVLws1Q8MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
      AHKZ3PM1Ipxz5rb2ktOZ5G+AShA6dcGnGIWRW/HrH3BgvBABhBKu++IhBu4Hrp/P
      3Xg6hqZklmr30ZKLO6NgyrTOgTv+/IhauIYOzOyEs68kEnkFHmYuV5GSpPZyE9f9
      XshdCENJSi4JdJuYTboWc/yCsAbmlAPhEjxNA7oHKkgoI/eA3uMK3y01LXk0xcOh
      uCFzIGyvfR323czAfD3/4ZyjE9FCiU/0P10re5mVFUiOnnZIc4zP9/9jTS3BYyXE
      lzhpYn0LdcL8ci8LxCv1OjcgCNeC6kRgzgUhbrUmVHAQmC2+c4tmUq/HQnXA0LWI
      cgSs46l4xpaiLnDeBytVdWo=
      -----END CERTIFICATE-----
    privatekey: |
    [...]
```

Copy the CA certificate content into a file and set the `VAULT_CACERT` environment variable to reference this file:

```bash
export VAULT_CAPATH=/path/to/vault_ca.pem
```

Identify the vault address by setting the `VAULT_ADDR` environment variable using the Vault URL which is retrieved through `show-proxied-endpoints` action.

```bash
export VAULT_ADDR="https://10.0.0.4/vault-vault-k8s"
```

You can now run vault commands against the vault unit.

```bash
vault status
vault operator raft list-peers
```

## Integrations

### Prometheus

```bash
juju integrate vault-k8s:metrics-endpoint prometheus-k8s:metrics-endpoint
```

## OCI Images

- Vault: ghcr.io/canonical/vault:1.15.2

<!-- LINKS -->

[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/
