# Contract: VaultClient.generate_self_signed_ca

**Interface**: `VaultClient.generate_self_signed_ca()`  
**Type**: Internal library method (vault-package)  
**Consumers**: `PKIManager`  

## Signature

```python
def generate_self_signed_ca(
    self,
    mount: str,
    common_name: str,
    ttl: str,
    sans_dns: list[str] | None = None,
    country: str | None = None,
    province: str | None = None,
    locality: str | None = None,
    organization: str | None = None,
    organizational_unit: str | None = None,
) -> tuple[str, str]:
    """Generate a self-signed CA certificate in Vault.

    Uses the PKI secrets engine's /root/generate/internal endpoint.
    Returns the certificate (PEM) and the private key (PEM).

    Args:
        mount: The mount point for the PKI backend.
        common_name: The common name for the CA certificate.
        ttl: The validity period (e.g., "87600h" for 10 years).
        sans_dns: Subject alternative DNS names.
        country: Country name for the certificate.
        province: Province/state name.
        locality: Locality name.
        organization: Organization name.
        organizational_unit: Organizational unit name.

    Returns:
        Tuple of (certificate_pem, private_key_pem).

    Raises:
        VaultClientError: If Vault returns an error.
    """
```

## Preconditions

- The PKI secrets engine must be enabled at the given mount point
- The caller must have permission to call `pki/root/generate/internal`
- The mount point must not already have a root CA configured (or Vault must allow regeneration)

## Postconditions

- Vault has a new root CA configured at the given mount point
- The returned certificate and private key are valid PEM strings
- The certificate is self-signed (issuer == subject)

## Error Handling

| Error | Cause | Handling |
|-------|-------|----------|
| `VaultClientError` | Vault API error (InvalidRequest, Forbidden, etc.) | Raised to caller; caller logs and handles gracefully |

## Example

```python
vault = VaultClient(url="https://vault:8200", ca_cert_path="/vault/certs/ca.pem")
vault.authenticate(Token("root-token"))

cert, key = vault.generate_self_signed_ca(
    mount="charm-pki",
    common_name="Vault Self-Signed CA",
    ttl="87600h",
    sans_dns=["vault-ca.example.com"],
)
```
