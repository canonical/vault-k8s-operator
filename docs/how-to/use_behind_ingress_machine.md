# Use Vault behind an Ingress (Machine)

It is recommended to run Vault behind an ingress. In this guide we will list the necessary steps to achieve this using the [haproxy operator](https://charmhub.io/haproxy?channel=2.8/stable).

## Pre-requisites

- Vault deployed on a Juju model on a machine controller (non-K8s)

## Steps

**Note**: Some features required by this setup are only available on edge in HAProxy.

Deploy haproxy

```bash
juju deploy haproxy --channel 2.8/edge
```

Deploy Ingress Configurator Charm to the same machine as HAProxy.

```bash
juju deploy ingress-configurator --channel latest/edge --to <machine>
```

Configure the Configurator charm

```bash
juju config ingress-configurator hostname=<your hostname>
```

```bash
juju config ingress-configurator backend-protocol=https
```

Deploy Self Signed Certificates Operator

```bash
juju deploy self-signed-certificates --channel 1/stable
```

Establish the required integrations

```bash
juju integrate vault:tls-certificates-access self-signed-certificates
```

```bash
 juju integrate vault:ingress ingress-configurator
```

```bash
juju integrate ingress-configurator:haproxy-route haproxy
```

```bash
juju integrate self-signed-certificates haproxy:receive-ca-certs
```

```bash
juju integrate haproxy:certificates self-signed-certificates
```

The `ingress` (between Vault and the ingress-configurator) and the `haproxy-route` (between ingress-configurator and HAProxy) integrations allow accessing Vault through the proxy.

Now in the relation data of the ingress integration in Vault we will find the URL that we can use to access Vault

```bash
juju show-unit vault/0

# Sample Action Output
Running operation 1 with 1 task
- relation-id: 3
    endpoint: ingress
    related-endpoint: ingress
    application-data:
      ingress: '{"url": "https://<your hostname>/"}'
    related-units:
      ingress-configurator/0:
        in-scope: true
        data:
          egress-subnets: 10.185.233.12/32
          ingress-address: 10.185.233.12
          private-address: 10.185.233.12
```

Make sure your DNS resolves the hostname to the IP of HAProxy.

Retrieve the Juju secrets list:

```bash
user@ubuntu:~$ juju secrets --format=yaml
ck0i0h3q457c7bgte4kg:
  revision: 1
  owner: vault
  label: vault-ca-certificate
  created: 2023-09-13T02:36:57Z
  updated: 2023-09-13T02:36:57Z
ck0i0krq457c7bgte4l0:
  revision: 1
  owner: vault
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
  owner: vault
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

Read the `active-ca-certificates` secret content of `self-signed-certificates` as we used it to sign the access certificates of Vault:

```bash
user@ubuntu:~$ juju show-secret cks0s1c24l7c77v23p80 --reveal
cks0s1c24l7c77v23p80:
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

Copy the CA certificate content into a file and set the `VAULT_CAPATH` environment variable to reference this file:

```bash
export VAULT_CAPATH=/path/to/vault_ca.pem
```

Identify the vault address by setting the `VAULT_ADDR` environment variable using the Vault URL which is we fetched from the relation data earlier

```bash
export VAULT_ADDR="https://<your hostname>"
```

You can now run vault commands against the vault unit.

```bash
vault status
vault operator raft list-peers
```
