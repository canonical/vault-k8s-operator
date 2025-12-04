# Use Vault as an intermediate CA

In this how-to guide, we will configure Vault to act as an intermediate Certificate Authority (CA) using [Vault's PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki). Here [self-signed-certificates](https://charmhub.io/self-signed-certificates) will be the parent CA and [tls-certificates-requirer](https://charmhub.io/tls-certificates-requirer) will be the charm requesting a certificate to Vault.

The certificates issued by Vault will have a validity period that is half of its intermediate CA's, which is determined by the root provider's configuration, in this case, the self-signed certificates.

![image|690x129](upload://9Fqp2fx6aXCVzucptBL9PdlJp8n.png)

1. Configure Vault's common name

[note]Vault PKI will only allow issuing certificates for the subdomains of the common_name configured here, it will reject any requests using different domains in their subject.[/note]

```shell
juju config vault common_name=<your domain name>
```

2. Deploy the parent CA

```shell
juju deploy self-signed-certificates --channel 1/stable
```

3. Integrate Vault with its parent CA

```shell
juju integrate vault:tls-certificates-pki self-signed-certificates
```

4. Deploy `tls-certificates-requirer`

[note]The common name must be a subdomain of the Vault common name[/note]

```shell
juju deploy tls-certificates-requirer --config common_name=<your domain name>  --config sans_dns=<your domain name>
```

5. Integrate TLS Certificates Requirer with Vault

```shell
juju integrate tls-certificates-requirer vault:vault-pki
```

6. Retrieve the certificate

```shell
juju run tls-certificates-requirer/leader get-certificate
```
