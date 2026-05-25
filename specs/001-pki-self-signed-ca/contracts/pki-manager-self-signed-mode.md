# Contract: PKIManager Self-Signed CA Mode

**Interface**: `PKIManager` (modified constructor and methods)  
**Type**: Internal library class (vault-package)  
**Consumers**: `charm.py` (k8s and machine charms)  

## Constructor Changes

```python
def __init__(
    self,
    charm: CharmBase,
    vault_client: VaultClient,
    certificate_request_attributes: CertificateRequestAttributes,
    mount_point: str,
    role_name: str,
    allowed_domains: str | None,
    allow_subdomains: bool | None,
    allow_wildcard_certificates: bool | None,
    allow_any_name: bool | None,
    allow_ip_sans: bool | None,
    organization: str | None,
    organizational_unit: str | None,
    country: str | None,
    province: str | None,
    locality: str | None,
    vault_pki: TLSCertificatesProvidesV4,
    tls_certificates_pki: TLSCertificatesRequiresV4,
    self_signed_ca: bool = False,  # NEW PARAMETER
):
```

**New parameter**:
- `self_signed_ca`: When `True`, the manager operates in self-signed CA mode and does not require or use the `tls_certificates_pki` relation.

## configure() Behavior

### Self-Signed Mode (`self_signed_ca=True`)

1. Check leader status (skip if not leader)
2. Enable PKI secrets engine at mount point
3. Call `_configure_self_signed_ca()`:
   a. Check Juju secret for existing CA cert + key
   b. If exists and matches current config, retrieve it
   c. If not exists or config changed, generate new CA via `VaultClient.generate_self_signed_ca()`
   d. Store new cert + key in Juju secret
   e. Import CA into Vault via `VaultClient.import_ca_certificate_and_key()`
4. Update PKI role with appropriate TTL (half of CA validity)
5. Make latest issuer default

### External CA Mode (`self_signed_ca=False`)

Unchanged from existing behavior.

## sync() Behavior

### Self-Signed Mode (`self_signed_ca=True`)

1. Check leader status (skip if not leader)
2. Get outstanding certificate requests from `vault_pki`
3. For each request:
   a. Check PKI role exists
   b. Get CA certificate from Juju secret (not from relation)
   c. Calculate allowed cert validity
   d. Sign CSR via `VaultClient.sign_pki_certificate_signing_request()`
   e. Build `ProviderCertificate` and set on relation

### External CA Mode (`self_signed_ca=False`)

Unchanged from existing behavior.

## Preconditions

- Vault is initialized and unsealed
- `pki_ca_common_name` is set and valid
- In self-signed mode: no `tls-certificates-pki` relation exists (or it exists but is ignored)

## Postconditions

- PKI secrets engine is enabled
- A valid CA issuer is configured
- PKI role is created/updated
- Outstanding certificate requests are fulfilled

## State Diagram

```
                    ┌─────────────────┐
                    │   PKIManager    │
                    │  (initialized)  │
                    └────────┬────────┘
                             │ configure()
                             ▼
              ┌──────────────────────────────┐
              │      self_signed_ca=True?     │
              └─────────────┬────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │ Yes                        │ No
              ▼                            ▼
    ┌─────────────────┐          ┌─────────────────┐
    │ _configure_self │          │ _configure_ext  │
    │   _signed_ca()  │          │    _ca()        │
    │  (Juju secret   │          │  (tls-cert-     │
    │   + Vault gen)  │          │   pki relation) │
    └────────┬────────┘          └────────┬────────┘
             │                            │
             └─────────────┬──────────────┘
                           ▼
                 ┌─────────────────┐
                 │  _update_role() │
                 │ make_default()  │
                 └─────────────────┘
```
