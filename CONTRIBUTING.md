# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. You can find the contributing guidelines in each charm's directory if you want to contribute to one of these charms.

Tool settings for linting, static analysis, and testing are configured in the repo-level `pyproject.toml`. Project-specific settings for `ruff` and `pyright` may be defined in individual `pyproject.toml` files if necessary, but prefer the repo-level `pyproject.toml` where possible.

## Common code between the Machine and K8s charms

Shared code used by both the Vault machine and K8s charms is defined in `vault-package`. This code is vendored into both charms so that `charmcraft pack` can run in each directory without any additional information. Vendored code **must** be in sync to merge to `main`.

Vendored code is updated for a charm when running any of its `tox` commands. When editing shared code, it is best practice to run `tox` for both charms to ensure the changes work for both charms. However, you can also manually vendor the shared code by running the following command in the `k8s/` and `machine/` directories:

```shell
make vendor-shared-code
```

## Documentation

Serve the documentation locally with:

```shell
cd docs
make run
```

## CI and Pull Request Labels

On PRs, standard checks run by default and can be skipped for any change when the model
chooses `skip` with at least 0.8 confidence and choice probability, using complete,
revision-verified evidence. Required prerequisites still run even if proposed for skipping.
An AMD64 group whose latest execution on `main` failed or timed out is forced to run,
regardless of the model's skip decision. Successful reruns clear this override; skipped
executions do not. Missing or uncertain main results also require the affected group.
CI checks up to the latest 20 main CI runs to find each group's latest execution.
ARM64 and s390x are skipped by default, including when classification fails or is uncertain;
they run only for a confident model `run` decision or an explicit force-run label.
Pushes to `main` and release branches always run full CI on all architectures.
New PR runs cancel superseded runs for the same PR; main and release push runs remain
independent. Selection-dependent job conditions must remain cancellable (`!cancelled()`,
not `always()`), including when falling back after a failed decision.

Maintainers can force CI checks with these PR labels. Required prerequisites are included.

| Label | Runs |
| --- | --- |
| `run-all-ci` | All checks on all architectures |
| `run-shared-code-sync` | Shared-code synchronization |
| `run-k8s-quality` | Kubernetes lint, static analysis, and unit tests |
| `run-machine-quality` | Machine lint, static analysis, and unit tests |
| `run-k8s-build` | Kubernetes AMD64 build |
| `run-machine-build` | Machine AMD64 build |
| `run-k8s-integration` | Kubernetes AMD64 integration tests |
| `run-machine-integration` | Machine AMD64 integration tests |
| `test-arm` | ARM64 builds and integration tests |
| `test-s390x` | s390x builds and integration tests |

Selection, retry, and maintenance details live alongside their implementations:
[CI selection](.github/workflows/ci-decision.yaml) and
[intermittent-failure retries](.github/workflows/retry-ci.yaml).
