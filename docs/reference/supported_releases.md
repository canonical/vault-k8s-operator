# Supported Releases

The following table summarizes supported release information for the Vault charms (Kubernetes and Machine).

| Charm type | Version/Channel | Base           | Architecture              |
| ---------- | --------------- | -------------- | ------------------------- |
| Kubernetes | `2.0/stable`    | `ubuntu@24.04` | `amd64`, `arm64`, `s390x` |
| Machine    | `2.0/stable`    | `ubuntu@24.04` | `amd64`, `arm64`, `s390x` |

## Recommended track and existing deployments

Vault charms 2.0 is the current Long Term Support (LTS) branch and the recommended track for all new deployments. Deploy new instances from `2.0/stable`.

All `1.x` tracks, including `1.16`, `1.18`, and `1.19`, are deprecated and should not be used for new deployments. Existing deployments should migrate to `2.0/stable` using the [upgrade guide](../how-to/upgrade_1.1x_to_2.0.md).

Security patches will be provided for existing deployments on the `1.16` and `1.19` tracks. This security-patch commitment does not change the recommendation to migrate to `2.0/stable`.

## Release channels

Components follow the Charmhub channel model, with progressive promotion through risk levels:

- **edge**: Automated builds from commits into the sable branch for development and early testing.
- **beta**: Builds promoted from edge after initial validation. For broader testing.
- **candidate**: Builds promoted from beta after extended testing as release candidates for production.
- **stable**: Production-ready builds promoted from candidate after validation.

## Support commitment

For supported deployments, we commit to the following over the support time frame:

- Apply security patches
- Maintain documentation
- Publish new revisions of the underlying workload
- Provide an upgrade path with other supported releases

## Vault charms lifecycle and support

The Vault charms follow a downstream release model tied to [HashiCorp Vault following IBM (SC2)](https://developer.hashicorp.com/vault/docs/enterprise/support). This policy balances feature delivery with long-term infrastructure stability.

### Release cadence

Candidate and stable releases follow a 4-week cadence, offset by two weeks: each candidate release is promoted to stable two weeks later after full validation.

## Long Term Support (LTS) policy

- Every two years, aligned with the Ubuntu LTS and the latest HashiCorp Vault LTS, a new LTS channel is released for the charms. Vault charms 2.0 is the current LTS branch.
- New deployments should use `2.0/stable`.
- Each Vault LTS version receives 2 years of active bug support.
- Vault LTS versions receive 15 years of security maintenance through [Ubuntu Pro](https://ubuntu.com/about/release-cycle).
- When a new LTS channel is released, the previous LTS enters a 6-month deprecation grace period. Operators should migrate to a supported version within this window.
- All `1.x` tracks are deprecated. Existing deployments should migrate to `2.0/stable`.
- Security patches will be provided for existing deployments on the `1.16` and `1.19` tracks.

## Upgrade policy

The [1.1x to 2.0 upgrade guide](../how-to/upgrade_1.1x_to_2.0.md) supports upgrading directly from any 1.1x release it covers to 2.0.
