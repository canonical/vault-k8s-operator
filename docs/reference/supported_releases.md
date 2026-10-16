# Supported Releases

The following table summarizes supported release information for the Vault charms (Kubernetes and Machine).

| Charm type | Version/Channel | Base           | Architecture                 |
| ---------- | --------------- | -------------- | ---------------------------- |
| Kubernetes | `2.0/stable`    | `ubuntu@24.04` | `amd64`, `arm64`, `s390x`    |
| Machine    | `2.0/stable`    | `ubuntu@24.04` | `amd64`, `arm64`, `s390x`    |

## Release channels

Components follow the Charmhub channel model, with progressive promotion through risk levels:

- **edge**: Automated builds from commits into the sable branch for development and early testing.
- **beta**: Builds promoted from edge after initial validation. For broader testing.
- **candidate**: Builds promoted from beta after extended testing as release candidates for production.
- **stable**: Production-ready builds promoted from candidate after validation.

## Support commitment

We commit to the following over the whole support time frame:

- Apply security patches
- Maintain documentation
- Publish new revisions of the underlying workload
- Provide an upgrade path with other supported releases

## Vault charms lifecycle and support

### Vault charms

The Vault charms follows a downstream release model tied to [HashiCorp Vault following IBM (SC2)](https://developer.hashicorp.com/vault/docs/enterprise/support). This policy ensures a balance between rapid feature delivery and long-term infrastructure stability.

### Release cadence

Candidate and stable releases follow a 4-week cadence, offset by two weeks: each candidate release is promoted to stable two weeks later after full validation. These releases include new features, bug fixes, and performance patches.

## Long Term Support (LTS) policy

- Every two years, aligned with the Ubuntu LTS and the latest HashiCorp Vault LTS, a new LTS channel is released for the charms.
- Each Vault LTS version receives 2 years of active bug support.
- The Vault LTS version receives 15 years of security maintenance ([Ubuntu Pro](https://ubuntu.com/about/release-cycle))
- When a new LTS channel is released, the previous LTS enters a 6-month deprecation grace period. Operators must migrate to a supported version within this window.

## Upgrade policy

The Vault charms support upgrades between consecutive versions. To maintain a supported state, deployments should be upgraded to the next sequential LTS or feature release. Skipping versions is not validated and may lead to service interruption.
