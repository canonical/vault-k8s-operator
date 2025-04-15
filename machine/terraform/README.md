# Vault Terraform module

This folder contains a base [Terraform][Terraform] module for the `vault` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm deployment onto any Kubernetes environment managed by [Juju][Juju].

The base module is not intended to be deployed in separation (it is possible though), but should rather serve as a building block for higher level modules.

## Getting Started

### Pre-requisites

- A Machine environment
- A Juju controller bootstrapped onto the machine environment
- The Juju client
- Terraform

### Deploying Vault

On the host machine create a new directory called terraform:

```shell
mkdir terraform
```

Inside newly created terraform directory create a versions.tf file:

```shell
cd terraform
cat << EOF > versions.tf
terraform {
  required_providers {
    juju = {
      source  = "juju/juju"
      version = ">= 0.12.0"
    }
  }
}
EOF
```

Create a Terraform module containing Vault:

```shell
cat << EOF > main.tf
resource "juju_model" "demo" {
  name = "demo"
}

module "vault" {
  source = "git::https://github.com/canonical/vault-k8s-operator//machine/terraform"
  
  model      = juju_model.demo.name
}
EOF
```

Initialize Juju Terraform provider:

```shell
terraform init
```

Deploy the module:

```shell
terraform apply
```

## How-to

### Create integrations

Add the following content to your module's `main.tf` file to create the integration between the `vault` charm and other charms.

```text
resource "juju_integration" "vault-kv-integration" {
  model = var.model

  application {
    name     = module.some-app.app_name
    endpoint = module.some-app.vault-kv
  }

  application {
    name     = module.vault.app_name
    endpoint = module.vault.provides.vault-kv
  }
}
```

## Reference

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment options (Juju model name, channel or application name) also models the charm configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations), but also by exposing the application name.
- **versions.tf** - Defines the Terraform provider.

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[vault-integrations]: https://charmhub.io/vault/integrations
