# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Common Makefile for charm directories (machine/Makefile is a symlink to ../k8s/Makefile)

# We're using Make as a command runner, so always make (avoids need for .PHONY)
MAKEFLAGS += --always-make

# Copy shared package into the charm directory
vendor-shared-code:
	rsync --archive --delete ../vault-package/vault lib/

# Copy libs used by test charm
copy-test-libs:
	cp lib/charms/vault_k8s/v0/vault_kv.py tests/integration/vault_kv_requirer_operator/lib/charms/vault_k8s/v0/
	cp lib/vault/juju_facade.py tests/integration/vault_kv_requirer_operator/lib/vault/

