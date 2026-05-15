[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![GitHub tag](https://img.shields.io/github/v/tag/scanset/ESP-Agent-SDK?sort=semver)](https://github.com/scanset/ESP-Agent-SDK/tags)
# ESP Agent SDK

Build compliance scanners using [Endpoint State Policy (ESP)](https://github.com/scanset/Endpoint-State-Policy).

## Overview

The ESP Agent SDK is a self-contained CLI scanner that executes ESP policies against endpoint systems and outputs results as JSON. It includes reference implementations for common CTN (Collection Type Name) types via the bundled `contract_kit` module.

```
┌─────────────────────────────────────────────────────────────┐
│                     ESP Agent SDK                           │
├─────────────────────────────────────────────────────────────┤
│  agent/                                                     │
│  ├── src/                                                   │
│  │   ├── main.rs, cli.rs, scanner.rs, registry.rs ...       │
│  │   └── contract_kit/   Collectors, executors, contracts   │
│  ├── Cargo.toml                                             │
│  └── Makefile                                               │
├─────────────────────────────────────────────────────────────┤
│                  ESP Core (external, v2.2.3)                │
│  common, compiler, execution_engine                         │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Build

```bash
cd agent/
make build          # Debug build
make release        # Optimized release build
```

### Run

```bash
# Scan a single policy, console output only
make run ESP=../esp/policy.esp

# Scan a single policy and write the signed AssessorPackage envelope to a file
make run-output ESP=../esp/policy.esp OUT=assessor_package.json

# Batch scan a directory of policies (one envelope per run)
make run-batch ESP=../esp/ OUT=assessor_package.json
```

Every scan produces a single signed `AssessorPackage` envelope covering all
policies the run touched. Results are printed to the console unless `--quiet`
is set; `--output` (or `make run-output OUT=...`) also writes the JSON envelope
to a file.

### Cross-Compilation

```bash
make build-win      # Windows (x86_64-pc-windows-gnu)
make build-musl     # Linux static (x86_64-unknown-linux-musl)
make release-all    # All targets, release mode
```

### Development

```bash
make test           # Run tests
make lint           # Run clippy (strict)
make check-all      # Check all targets compile
make pre-commit     # Format, lint, test
```

## Guides

| Guide | Description |
|-------|-------------|
| [ESP Language Guide](./guides/ESP_Language_Guide.md) | Learn to write ESP policies |
| [Contract Development Guide](./guides/Contract_Development_Guide.md) | Extend with custom CTN types |

## Requirements

- Rust 1.92+
- For cross-compilation: `mingw-w64` (Windows), `musl-tools` (static Linux)

### Development Environment

**VS Code DevContainers (recommended):**

Open the repository in VS Code and select "Reopen in Container" when prompted. This provides a fully configured environment with all cross-compilation toolchains.

**Manual Docker:**

```bash
cd agent/
make docker-build
```

## License

Apache 2.0
