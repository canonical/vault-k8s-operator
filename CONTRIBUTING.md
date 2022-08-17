# Contributing

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate

## Testing

Testing for this project is done using `tox`. You can run the various tests like so:

```shell
tox -e lint      # code style
tox -e static    # static analysis
tox -e unit      # unit tests
```
