# Vault Charms 1.18 Release Notes

## What's New:

- The K8s Charm now uses 1.18.x Vault OCI image and the Machine Charm uses the 1.18.x Vault Snap.
- Increased configurability of the charm, giving the user more control over the configurations of PKI and ACME engines and over attributes of Vault's Certificates.
    - This removes the unnecessary constraint where Vault PKI issued certificates only for subdomains of its configured common name.


Full Changelog: [Changes compared to 1.17](https://github.com/canonical/vault-k8s-operator/compare/release-1.17...main)
