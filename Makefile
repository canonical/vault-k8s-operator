# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# We're using Make as a command runner, so always make (avoids need for .PHONY)
MAKEFLAGS += --always-make

# vendor-shared-code: Copy the shared code into the two charms that use it.
vendor-shared-code:
	rsync --archive --delete vault-package k8s/.vendored/
	rsync --archive --delete vault-package machine/.vendored/

copy-test-libs-k8s:
	cp k8s/lib/charms/vault_k8s/v0/vault_kv.py k8s/tests/integration/vault_kv_requirer_operator/lib/charms/vault_k8s/v0/
	cp vault-package/src/vault/juju_facade.py k8s/tests/integration/vault_kv_requirer_operator/lib/vault/

copy-test-libs-machine:
	cp machine/lib/charms/vault_k8s/v0/vault_kv.py machine/tests/integration/vault_kv_requirer_operator/lib/charms/vault_k8s/v0/
	cp vault-package/src/vault/juju_facade.py machine/tests/integration/vault_kv_requirer_operator/lib/vault/
