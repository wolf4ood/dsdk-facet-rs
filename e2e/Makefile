# Makefile for E2E tests
# Makes it easier to run common commands

.PHONY: help setup verify build build-siglet rebuild-siglet test test-fast test-verbose cleanup clean all

# Detect if cargo-nextest is available
NEXTEST_INSTALLED := $(shell command -v cargo-nextest 2> /dev/null)

help:
	@echo "E2E Test Commands:"
	@echo "  make setup          - Setup Kind cluster and deploy Vault"
	@echo "  make verify         - Verify E2E environment is ready"
	@echo "  make build          - Build the vault-test Docker image"
	@echo "  make build-siglet   - Build Siglet image (full build, ~2-5 min)"
	@echo "  make rebuild-siglet - Rebuild Siglet image (fast on Linux, falls back to full on macOS)"
	@echo "  make test           - Build all images and run E2E tests"
	@echo "  make test-fast      - Fast rebuild and test (for development)"
	@echo "  make test-verbose   - Build images and run E2E tests with verbose output"
	@echo "  make cleanup        - Delete Kind cluster"
	@echo "  make clean          - Clean Rust build artifacts"
	@echo "  make all            - Setup, run tests, and cleanup"
	@echo ""
	@echo "Test runner: $(if $(NEXTEST_INSTALLED),cargo-nextest (installed),cargo test (fallback))"
	@echo "  Install nextest for faster tests: cargo install cargo-nextest --locked"

setup:
	@./scripts/setup.sh

verify:
	@./scripts/verify-setup.sh

build:
	@./scripts/build-and-load-image.sh

build-siglet:
	@./scripts/build-and-load-siglet.sh

rebuild-siglet:
	@SIGLET_BUILD_MODE=iterative ./scripts/build-and-load-siglet.sh

test: build build-siglet
ifdef NEXTEST_INSTALLED
	@echo "Running tests with cargo-nextest..."
	@cd .. && cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only
else
	@echo "cargo-nextest not found, using cargo test (install nextest for faster tests)"
	@echo "  cargo install cargo-nextest --locked"
	@cd .. && cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored
endif

test-fast: build rebuild-siglet
ifdef NEXTEST_INSTALLED
	@echo "Running tests with cargo-nextest..."
	@cd .. && cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only
else
	@echo "cargo-nextest not found, using cargo test (install nextest for faster tests)"
	@cd .. && cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored
endif

test-verbose: build build-siglet
ifdef NEXTEST_INSTALLED
	@echo "Running tests with cargo-nextest..."
	@cd .. && cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only --no-capture
else
	@echo "cargo-nextest not found, using cargo test (install nextest for faster tests)"
	@cd .. && cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --nocapture
endif

cleanup:
	@./scripts/cleanup.sh

clean:
	@cd .. && cargo clean

all: setup test cleanup
