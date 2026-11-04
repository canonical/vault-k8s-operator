# Vault Charms

**Vault** is a tool for securely managing secrets used in modern computing (e.g. passwords, certificates, API keys).

**Vault Charms** for Kubernetes and Machines are used to deploy, and initialise and operate Vault with Juju.

The operator implements the tls-certificates interface supporting automatic certificate renewal, structured error reporting with standardised codes, and guaranteed responses (every certificate request receives either a certificate or a detailed error).

This documentation covers the Vault charms **2.0** track.

```{note}
All `1.x` tracks are deprecated. If you are running a `1.x` track, migrate to `2.0` using the [upgrade from 1.1x to 2.0 guide](how-to/upgrade_1.1x_to_2.0.md).
```

## In this documentation

````{grid} 1 1 2 2

```{grid-item-card}
:link: tutorial/

Tutorials
^^^

**Start here**: a hands-on introduction to Vault Charms for new users
```

```{grid-item-card}
:link: how-to/

How-to guides
^^^

**Step-by-step guides** covering key operations and common tasks
```

````

````{grid} 1 1 2 2

```{grid-item-card}
:link: reference/

**Reference**
^^^

**Technical information** - specifications, APIs, architecture
```

```{grid-item-card}
:link: explanation/

Explanation
^^^

**Discussion and clarification** of key topics
```

````

## Project and community

Vault charms are members of the Ubuntu family. It’s an open source project that warmly welcomes community projects, contributions, suggestions, fixes and constructive feedback.

- [Ubuntu Code of conduct](https://ubuntu.com/community/ethos/code-of-conduct)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/#tls:ubuntu.com)
- [Open a bug](https://github.com/canonical/vault-k8s-operator/issues)
- [Contribute](https://github.com/canonical/vault-k8s-operator/)

```{toctree}
:hidden:

tutorial/index
how-to/index
reference/index
explanation/index
```
