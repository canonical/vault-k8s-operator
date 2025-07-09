# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

ROOT_DIR := $(CURDIR)
K8S_CHARM_LIB := $(ROOT_DIR)/k8s/lib/vault
MACHINE_CHARM_LIB := $(ROOT_DIR)/machine/lib/vault

.PHONY: vendor-shared-code

# vendor-shared-code: Copy the shared code into the two charms that use it.
vendor-shared-code:
	rsync --archive --delete vault-package/vault k8s/lib/
	rsync --archive --delete vault-package/vault machine/lib/

copy-test-libs:
	cp $(ROOT_DIR)/k8s/lib/charms/vault_k8s/v0/vault_kv.py $(ROOT_DIR)/k8s/tests/integration/vault_kv_requirer_operator/lib/charms/vault_k8s/v0/
	cp $(ROOT_DIR)/k8s/lib/vault/*.py $(ROOT_DIR)/k8s/tests/integration/vault_kv_requirer_operator/lib/vault/
