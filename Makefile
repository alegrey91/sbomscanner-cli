BINARY_NAME := sbomscannerdb
BIN_DIR     := ./bin
BIN         := $(BIN_DIR)/$(BINARY_NAME)

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd/sbomscannerdb
	@echo "built $(BIN)"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.PHONY: test
test:
	go test ./...

# Pinned to match the version the .golangci.yml config targets.
GOLANGCI_LINT_VERSION ?= v2.12.1

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...
