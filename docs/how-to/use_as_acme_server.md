# Use Vault as an ACME Server to obtain TLS certificates

In this how-to guide, we will configure Vault to act as an ACME server using [Vault's PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki).  Here [self-signed-certificates](https://charmhub.io/self-signed-certificates) will be the parent CA.

The certificates issued by Vault will have a validity period that is half of its intermediate CA's, which is determined by the root provider's configuration, in this case, the self-signed certificates.

1. Configure Vault's common name
```shell
juju config vault common_name=mydomain.com
```
2. Deploy the parent CA

```shell
juju deploy self-signed-certificates --channel 1/stable
```

3. Integrate Vault with its parent CA

```shell
juju integrate vault:tls-certificates-acme self-signed-certificates
```

Now the ACME server is accessible on `https://<Vault Address>:8200/v1/charm-acme/acme/directory`

Now you should be able to obtain a certificate from Vault using an ACME client, for example [Lego](https://go-acme.github.io/lego/).