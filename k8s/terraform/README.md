# Vault K8s Terraform module

This folder contains a base [Terraform][Terraform] module for the `vault-k8s` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm deployment onto any Kubernetes environment managed by [Juju][Juju].

The base module is not intended to be deployed in separation (it is possible though), but should rather serve as a building block for higher level modules.

## Getting Started

**Pre-requisites**

The following tools needs to be installed and should be running in the environment. Please [set up your environment][set-up-environment] before deployment.

- A Kubernetes cluster
- Juju
- Juju controller bootstrapped onto the K8s cluster
- Terraform

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

Create a Terraform module containing Vault K8s:

```shell
cat << EOF > main.tf
resource "juju_model" "demo" {
  name = "demo"
}

module "vault-k8s" {
  source = "git::https://github.com/canonical/vault-k8s-operator//k8s/terraform"
  
  model = "demo"
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

Add the following content to your module's `main.tf` file to create the integration between the `vault-k8s` charm and other charms.

```text
resource "juju_integration" "vault-kv-integration" {
  model = var.model

  application {
    name     = module.some-app.app_name
    endpoint = module.some-app.vault-kv
  }

  application {
    name     = module.vault-k8s.app_name
    endpoint = module.vault-k8s.provides.vault-kv
  }
}
```

## Reference

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment options (Juju model name, channel or application name) also models the charm configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily by defining potential integration endpoints (charm integrations), but also by exposing the application name.
- **versions.tf** - Defines the Terraform provider.

## Useful links

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[vault-k8s-integrations]: https://charmhub.io/vault-k8s/integrations
[set-up-environment]: [https://discourse.charmhub.io/t/set-up-your-development-environment-with-microk8s-for-juju-terraform-provider/13109#prepare-development-environment-2]
