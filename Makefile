BINARY_NAME := sbomscanner-cli
BIN_DIR     := ./bin
BIN         := $(BIN_DIR)/$(BINARY_NAME)

# Stamp the binary with a version. Override at build time:
#   make build VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Local-registry test settings. Override on the command line, e.g.
#   make test-local REGISTRY_PORT=5555 REPO=my-db
REGISTRY_NAME ?= sbomscanner-local-registry
REGISTRY_PORT ?= 5000
REPO          ?= sbomscanner-db
TAG           ?= latest
REF           := localhost:$(REGISTRY_PORT)/$(REPO):$(TAG)

# Auto-detect docker or podman. Override with CONTAINER_CLI=podman if needed.
CONTAINER_CLI ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .
	@echo "built $(BIN) ($(VERSION))"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

# --- Local-registry smoke test ----------------------------------------------
#
# Runs the full get -> pack -> push loop against a throwaway registry:2
# container on localhost:$(REGISTRY_PORT). The registry is left running so you
# can poke at it afterwards; `make test-local-clean` tears it down.
#
# Requirements:
#   - docker or podman on PATH (override with CONTAINER_CLI=...)
#   - curl + jq for the verification step
#   - ~/.docker/config.json exists (the push command requires it; we create an
#     empty one if it's missing so first-time users don't get blocked)

.PHONY: test-local
test-local: build test-local-registry test-local-docker-config
	@echo ">>> get all"
	$(BIN) get all
	@echo ">>> pack"
	$(BIN) pack
	@echo ">>> push --plain-http $(REF)"
	$(BIN) push --plain-http $(REF)
	@echo ">>> verifying against registry API"
	@curl -sf http://localhost:$(REGISTRY_PORT)/v2/$(REPO)/tags/list \
		| (command -v jq >/dev/null && jq . || cat)
	@echo ""
	@echo ">>> manifest:"
	@curl -sf -H "Accept: application/vnd.oci.image.manifest.v1+json" \
		http://localhost:$(REGISTRY_PORT)/v2/$(REPO)/manifests/$(TAG) \
		| (command -v jq >/dev/null && jq . || cat)
	@echo ""
	@echo "OK. Registry left running as '$(REGISTRY_NAME)'."
	@echo "Tear down with: make test-local-clean"

# Start the registry container if it isn't already running. Idempotent.
.PHONY: test-local-registry
test-local-registry:
	@if [ -z "$(CONTAINER_CLI)" ]; then \
		echo "error: neither docker nor podman found on PATH"; exit 1; \
	fi
	@if $(CONTAINER_CLI) ps --format '{{.Names}}' | grep -qx $(REGISTRY_NAME); then \
		echo "registry '$(REGISTRY_NAME)' already running on :$(REGISTRY_PORT)"; \
	else \
		echo "starting registry '$(REGISTRY_NAME)' on :$(REGISTRY_PORT)"; \
		$(CONTAINER_CLI) run -d --rm --name $(REGISTRY_NAME) \
			-p $(REGISTRY_PORT):5000 registry:2 >/dev/null; \
		echo "waiting for registry to become ready..."; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			if curl -sf http://localhost:$(REGISTRY_PORT)/v2/ >/dev/null; then break; fi; \
			sleep 1; \
		done; \
	fi

# Ensure ~/.docker/config.json exists — the push command exits non-zero if it
# doesn't. An empty JSON object is a valid config and permits anonymous pushes.
.PHONY: test-local-docker-config
test-local-docker-config:
	@if [ ! -f "$$HOME/.docker/config.json" ]; then \
		echo "creating minimal $$HOME/.docker/config.json"; \
		mkdir -p $$HOME/.docker; \
		echo '{}' > $$HOME/.docker/config.json; \
	fi

.PHONY: test-local-clean
test-local-clean:
	@if [ -z "$(CONTAINER_CLI)" ]; then \
		echo "error: neither docker nor podman found on PATH"; exit 1; \
	fi
	-@$(CONTAINER_CLI) rm -f $(REGISTRY_NAME) 2>/dev/null && \
		echo "removed registry '$(REGISTRY_NAME)'" || \
		echo "registry '$(REGISTRY_NAME)' was not running"
