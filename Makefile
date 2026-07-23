.PHONY: help test-providerroutes

GO_CACHE_DIR ?= $(TMPDIR)/aikey-go-build-cache

help:
	@echo "test-providerroutes  Run providerroutes unit tests and vet checks"

test-providerroutes:
	cd providerroutes && GOCACHE="$(GO_CACHE_DIR)" go vet ./...
	cd providerroutes && GOCACHE="$(GO_CACHE_DIR)" go test ./... -count=1
