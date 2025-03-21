# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

ROOT_DIR := $(CURDIR)
K8S_CHARM_LIB := $(ROOT_DIR)/k8s/lib
MACHINE_CHARM_LIB := $(ROOT_DIR)/machine/lib

.PHONY: vendor-libs

# vendor-libs: Fetches the lib from the k8s charm lib directory to the machine charm lib directory.
vendor-libs:
	cp $(K8S_CHARM_LIB)/*.py $(MACHINE_CHARM_LIB)/
