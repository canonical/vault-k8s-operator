# TLS

TLS is always used between the Vault units and from a Vault client to the server. By default, the charm generates self-signed certificates, and users can opt for a different TLS provider by leveraging the tls-certificates-access integration. To learn more about the various TLS providers in the Juju ecosystem, read [this topic](https://charmhub.io/topics/security-with-x-509-certificates).

When Vault's access certificate is issued by an intermediate CA, use `receive-ca-cert` to obtain the root CA certificate and establish trust. For example, with self-signed-certificates as the root CA:

```shell
juju integrate vault:receive-ca-cert self-signed-certificates:send-ca-cert
```

```{image} ../images/tls.png
:alt: TLS
:align: center
```
