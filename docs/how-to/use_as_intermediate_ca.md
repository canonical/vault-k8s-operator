# Use Vault as an intermediate CA

In this how-to guide, we will configure Vault to act as an intermediate Certificate Authority (CA) using [Vault's PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki). Here [self-signed-certificates](https://charmhub.io/self-signed-certificates) will be the parent CA and [tls-certificates-requirer](https://charmhub.io/tls-certificates-requirer) will be the charm requesting a certificate to Vault.

The certificates issued by Vault will have a validity period that is half of its intermediate CA's, which is determined by the root provider's configuration, in this case, the self-signed certificates.

![image|690x129](upload://9Fqp2fx6aXCVzucptBL9PdlJp8n.png)

```{note}
Vault PKI will only allow issuing certificates depending on how it is configured, please see `pki_allow_subdomains`, `pki_allowed_domains`, `pki_allow_any_name` and `pki_allow_wildcard_certificates`
```

1. Configure Vault's common name

    ```shell
    juju config vault pki_ca_common_name=mydomain.com
    ```

2. Configure Vault PKI Engine to allow issuing certificates for subdomains

    ```shell
    juju config vault pki_allow_subdomains=true
    ```

3. Deploy the parent CA

    ```shell
    juju deploy self-signed-certificates --channel 1/stable
    ```

4. Integrate Vault with its parent CA

    ```shell
    juju integrate vault:tls-certificates-pki self-signed-certificates
    ```

5. Deploy `tls-certificates-requirer`

    ```shell
    juju deploy tls-certificates-requirer --config common_name=demo.mydomain.com  --config sans_dns=demo.mydomain.com
    ```

6. Integrate TLS Certificates Requirer with Vault

    ```shell
    juju integrate tls-certificates-requirer vault:vault-pki
    ```

7. Retrieve the certificate

    ```shell
    juju run tls-certificates-requirer/leader get-certificate
    ```
