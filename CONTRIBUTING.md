# Contributing

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate


## Testing

### Unit tests

```bash
tox -e unit
```

### Static analysis

```bash
tox -e static
```

### Linting

```bash
tox -e lint
```

## Publishing

To upload a new version of the OCI image:

```bash
charmcraft upload-resource vault-k8s vault-image --image=vault:latest
```

To upload a new version of the charm:
```bash
charmcraft pack
charmcraft upload vault-k8s_ubuntu-20.04-amd64.charm
```

To publish a new version of the charm

```bash
charmcraft release vault-k8s --revision=<charm version> --resource=vault-image:<oci image version> --channel=edge
```
