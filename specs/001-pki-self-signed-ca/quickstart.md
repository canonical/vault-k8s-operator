# Quickstart: PKI Self-Signed CA

**Feature**: PKI Self-Signed CA  
**Date**: 2026-05-25

## Prerequisites

- A Juju model with Vault deployed and initialized
- The Vault charm has `vault-pki` relation endpoint available
- No external CA charm (e.g., `self-signed-certificates`) is related to Vault's `tls-certificates-pki` endpoint

## Enable Self-Signed PKI

### 1. Configure the CA common name

```bash
juju config vault pki_ca_common_name="vault-ca.example.com"
```

### 2. (Optional) Configure additional CA attributes

```bash
juju config vault pki_ca_sans_dns="vault-ca.example.com,ca.example.com"
juju config vault pki_ca_country_name="US"
juju config vault pki_ca_state_or_province_name="California"
juju config vault pki_ca_locality_name="San Francisco"
juju config vault pki_ca_organization="Example Corp"
juju config vault pki_ca_organizational_unit="Security"
```

### 3. Relate a certificate requirer

```bash
juju deploy tls-certificates-requirer --config common_name="app.example.com"
juju integrate vault:vault-pki tls-certificates-requirer:certificates
```

### 4. Verify certificates are issued

```bash
juju status
# The requirer should show "Unit certificate is available"
```

## Switch from External CA to Self-Signed CA

If you previously used an external CA charm:

```bash
# Remove the external CA relation
juju remove-relation vault:self-signed-certificates

# The charm will automatically transition to self-signed CA mode
# and generate a new CA certificate
```

## Switch from Self-Signed CA to External CA

```bash
# Deploy and relate an external CA charm
juju deploy self-signed-certificates
juju integrate vault:tls-certificates-pki self-signed-certificates:certificates

# The charm will automatically switch to external CA mode
# and request an intermediate CA from the external provider
```

## Rotate the Self-Signed CA

Change the common name (or any CA attribute) to trigger rotation:

```bash
juju config vault pki_ca_common_name="vault-ca-v2.example.com"
```

The charm will:
1. Generate a new self-signed CA
2. Import it as a new issuer in the PKI mount
3. Set it as the default issuer
4. New certificates will be signed by the new CA

## Troubleshooting

### Charm shows "pki_ca_common_name is not set"

```bash
juju config vault pki_ca_common_name="your-domain.com"
```

### Charm shows blocked status with "tls-certificates-pki relation is missing"

This should NOT happen in self-signed mode. If it does:
- Check that `pki_ca_common_name` is valid
- Check charm logs: `juju debug-log --include vault`

### Certificates not being issued

- Verify Vault is initialized and unsealed
- Check that the `vault-pki` relation is established
- Check charm logs for PKI role or signing errors
