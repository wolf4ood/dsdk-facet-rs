# End-to-End Tests for Kubernetes Vault Integration

This directory contains E2E tests for Kubernetes-based JWT authentication with HashiCorp Vault using the sidecar pattern.

## Prerequisites

- **Docker**: Container runtime
- **Kind**: Kubernetes in Docker
- **kubectl**: Kubernetes CLI

## Quick Start

Setup cluster, deploy infrastructure, and run tests:

```bash
make all
```

## Development Workflow

```bash
cd e2e
make test-fast  # Rebuilds images and runs tests
```

### Initial Setup (one time)

```bash
cd e2e
make setup  # Sets up cluster, Vault, and builds all images
```

### Manual Builds

```bash
make build-siglet    # Full build (first time: 6+ min)
make rebuild-siglet  # Fast rebuild (~20-30s)
make build           # Build vault-test
```

## Build Performance

Builds use **cargo-chef** for dependency caching:
- **First build**: 5-6 minutes (builds all dependencies)
- **Rebuilds**: 20-30 seconds (only recompiles changed code)

No configuration needed - automatically enabled on macOS and Linux.

## Test Runner

This project supports both `cargo test` and `cargo nextest`. Nextest is **optional but recommended** for:
- Faster test execution with better parallelization
- Cleaner output with per-test timing
- Automatic retry of flaky tests
- JUnit report generation for CI

### Install cargo-nextest (optional)

```bash
cargo install cargo-nextest --locked
```

The Makefile and scripts automatically detect if nextest is installed and use it when available, falling back to `cargo test` if not.

## Run Specific Tests

### With cargo-nextest (recommended)

```bash
# Just Siglet tests
cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only -E 'test(siglet_e2e)'

# Single test
cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only -E 'test(test_signaling_operations)' --no-capture

# All e2e tests
cargo nextest run --package dsdk-facet-e2e-tests --features e2e --run-ignored only
```

### With cargo test (fallback)

```bash
# All e2e tests
cargo test --package dsdk-facet-e2e-tests --features e2e -- --ignored --nocapture

# Single test
cargo test --package dsdk-facet-e2e-tests --features e2e test_signaling_operations -- --ignored --nocapture
```

**Note**: Tests support parallel execution thanks to unique pod names (PID-based). Up to 2 e2e tests can run concurrently with nextest.
 