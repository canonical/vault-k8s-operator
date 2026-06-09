# Feature Specification: PKI Self-Signed CA

**Feature Branch**: `001-pki-self-signed-ca`  
**Created**: 2026-05-22  
**Status**: Draft  
**Input**: User description: "The goal is to allow this charm to enable pki without the need of an external CA charm, this should achieved using a Vault self-signed CA"

## User Scenarios & Testing

### User Story 1 - Enable PKI without external CA (Priority: P1)

As a Juju operator deploying Vault, I want to enable the PKI secrets engine without requiring a separate `tls-certificates-pki` relation to an external CA charm (e.g., self-signed-certificates). When `pki_ca_common_name` is configured but no external CA relation exists, the Vault charm should generate a self-signed CA certificate within Vault and import it directly into the existing PKI mount as the intermediate CA, then use it to issue certificates for `vault-pki` requirers.

**Why this priority**: This is the core value of the feature. Many operators do not want the operational overhead of deploying and managing a separate CA charm when Vault itself is capable of acting as a CA. Removing the external dependency simplifies deployment and reduces charm sprawl.

**Independent Test**: Can be fully tested by configuring `pki_ca_common_name` on a Vault charm that has `vault-pki` relations but no `tls-certificates-pki` relation. Certificates should be successfully issued to requirers.

**Acceptance Scenarios**:

1. **Given** the Vault charm is active and unsealed, **When** `pki_ca_common_name` is set and there is no `tls-certificates-pki` relation, **Then** the charm enables the PKI secrets engine, generates a self-signed CA certificate, imports it as the intermediate CA into the existing PKI mount, and the charm status remains active.
2. **Given** the Vault charm has a `vault-pki` relation and a self-signed CA is configured, **When** a requirer requests a certificate, **Then** the certificate is signed by the Vault self-signed CA and provided to the requirer. The certificate chain sent to the requirer contains the self-signed CA as both issuer and root.
3. **Given** the Vault charm is configured with a self-signed CA, **When** the `pki_ca_common_name` config value changes, **Then** a new self-signed CA is generated, imported into the PKI mount as a new issuer, made the default issuer, and the old issuer is cleaned up.

---

### User Story 2 - Hybrid mode with external CA (Priority: P2)

As a Juju operator deploying Vault, I want the charm to continue supporting the existing mode where an external CA charm provides the intermediate CA certificate via the `tls-certificates-pki` relation. When both the external relation and `pki_ca_common_name` are present, the external CA takes precedence.

**Why this priority**: Backward compatibility is critical. Existing deployments that rely on an external CA must not break. This story ensures the feature is additive rather than disruptive.

**Independent Test**: Can be fully tested by relating Vault to an external CA charm via `tls-certificates-pki`, while also having `pki_ca_common_name` set. The external CA should still provide the intermediate certificate, and certificates should be issued as before.

**Acceptance Scenarios**:

1. **Given** the Vault charm has a `tls-certificates-pki` relation with an external CA and `pki_ca_common_name` is set, **When** the charm configures the PKI engine, **Then** the intermediate CA from the external relation is used (self-signed mode is not activated).
2. **Given** the Vault charm has an external CA relation and later the relation is removed, **When** the relation is gone but `pki_ca_common_name` is still set, **Then** the charm transitions to self-signed CA mode and generates a new CA certificate.

---

### User Story 3 - CA certificate lifecycle and rotation (Priority: P3)

As a Juju operator, I want the self-signed CA certificate to have a configurable validity period, and for the charm to handle CA rotation gracefully when the CA expires or when the configuration changes.

**Why this priority**: While important for production use, basic CA lifecycle management can be considered an enhancement after the core self-signed CA feature is functional. A reasonable default validity period (e.g., 10 years) is acceptable for many environments.

**Independent Test**: Can be fully tested by observing CA certificate expiry and ensuring the charm either auto-renews or provides a clear path for rotation.

**Acceptance Scenarios**:

1. **Given** a self-signed CA is configured, **When** the CA certificate approaches expiry (e.g., within 30 days), **Then** the charm either renews the CA automatically or sets a warning status indicating manual intervention is needed.
2. **Given** the operator changes `pki_ca_common_name`, **When** the change is applied, **Then** the charm generates a new self-signed CA and updates the default issuer accordingly.

---

### Edge Cases

- What happens when a `vault-pki` requirer requests a certificate before the self-signed CA is ready? The charm's existing logic defers certificate issuance until the PKI engine is fully configured and ready.
- This feature uses a single self-signed CA directly as the PKI intermediate CA, not a root CA + intermediate CA hierarchy. A proper root/intermediate hierarchy is out of scope and can be added as a future enhancement.
- How does the system handle the self-signed CA private key? It is stored securely in a Juju secret and only accessible to the leader unit.
- What happens if both `tls-certificates-pki` (external CA) and self-signed CA mode are possible at the same time? The system deterministically prefers the external CA and does not activate self-signed mode.
- What happens when the Vault is not initialized or sealed? PKI configuration is deferred until Vault is ready.
- What happens on unit leader change? The self-signed CA private key stored in Juju secrets remains accessible to the new leader.

## Requirements

### Functional Requirements

- **FR-001**: The charm MUST be able to enable the PKI secrets engine and configure a self-signed CA certificate when `pki_ca_common_name` is set and no `tls-certificates-pki` relation exists.
- **FR-002**: The self-signed CA certificate MUST be generated by Vault itself and imported directly into the existing PKI secrets engine mount as the intermediate CA. No separate root CA mount is required.
- **FR-003**: The self-signed CA private key MUST be stored securely in a Juju secret accessible only to the application (leader units).
- **FR-004**: When a `tls-certificates-pki` relation with an external CA exists, the charm MUST continue to use the external CA and MUST NOT activate self-signed CA mode.
- **FR-005**: The charm MUST issue certificates to `vault-pki` requirers using the self-signed CA just as it does with an external intermediate CA. The certificate chain sent to requirers MUST be valid for TLS validation.
- **FR-006**: The charm MUST support CA rotation (generation of a new self-signed CA) when `pki_ca_common_name` changes. The new CA MUST be imported as a new issuer in the same mount, set as the default, and the old issuer SHOULD be cleaned up. The charm MUST NOT issue leaf certificates with a validity period that exceeds the validity of the self-signed CA.
- **FR-007**: The charm MUST validate `pki_ca_common_name`, `pki_allowed_domains`, and `pki_ca_sans_dns` before enabling the self-signed CA.
- **FR-008**: The charm MUST set an appropriate status (active, blocked, or waiting) when PKI cannot be configured due to missing or invalid config or missing Vault readiness. In self-signed CA mode, the charm MUST NOT block simply because no `tls-certificates-pki` relation exists.

### Key Entities

- **Self-Signed CA Certificate**: The CA certificate generated by Vault and used to sign leaf certificates. It includes attributes such as common name, SANs DNS, validity period, and issuer details derived from charm config.
- **Self-Signed CA Private Key**: The private key corresponding to the self-signed CA certificate. Stored in a Juju secret and used only by the leader unit when configuring the PKI engine.
- **PKI Issuer**: The issuer entity within the Vault PKI secrets engine that corresponds to the self-signed (or external) CA. The default issuer is used for signing all certificates.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Operators can enable PKI and issue certificates without deploying any additional CA charm.
- **SC-002**: Existing deployments using an external CA continue to function unchanged after this feature is introduced.
- **SC-003**: 100% of certificate requests from `vault-pki` requirers are fulfilled (either with a valid certificate or a clear error) when a self-signed CA is configured.
- **SC-004**: The charm's blocked status for missing `tls-certificates-pki` relation is no longer shown when self-signed CA mode is active and functional.

## Assumptions

- Vault is initialized and unsealed before PKI configuration is attempted. The charm already handles deferring work when Vault is not ready.
- The operator has set a valid `pki_ca_common_name` if they want to use self-signed CA mode.
- The `vault-pki` relation interface remains unchanged; requirers do not need to know whether the CA is self-signed or external.
- A reasonable default validity period for the self-signed CA will be used (e.g., 10 years), unless the user explicitly configures one.
- The charm already has the necessary Vault client methods to generate, import, and manage CA certificates in the PKI engine.
- Integration tests similar to the existing PKI tests should be implemented to validate the new self-signed CA feature, and no regressions should be introduced.
