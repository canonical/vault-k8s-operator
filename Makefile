# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

ROOT_DIR := $(CURDIR)
K8S_CHARM_LIB := $(ROOT_DIR)/k8s/lib/vault
MACHINE_CHARM_LIB := $(ROOT_DIR)/machine/lib/vault
SHARED_LIBS := __init__.py juju_facade.py vault_autounseal.py vault_client.py vault_s3.py

.PHONY: vendor-libs check-vendored-libs

# vault_helpers.py and vault_managers.py contain platform-specific code and must be ported manually.
vendor-libs:
	@set -e; for file in $(SHARED_LIBS); do cp "$(K8S_CHARM_LIB)/$$file" "$(MACHINE_CHARM_LIB)/$$file"; done

check-vendored-libs:
	@for file in $(SHARED_LIBS); do \
		cmp -s "$(K8S_CHARM_LIB)/$$file" "$(MACHINE_CHARM_LIB)/$$file" || { \
			echo "Shared library differs: $$file (run make vendor-libs)"; exit 1; \
		}; \
	done
