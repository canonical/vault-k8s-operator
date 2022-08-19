# Contributing

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate

## Testing

```shell
tox -e lint      # code style
tox -e static    # static analysis
tox -e unit      # unit tests
```
