# ESP Agent

**Compliance scanning agent using ESP (Endpoint State Policy) files.**

The ESP Agent executes ESP policies against endpoint systems and produces compliance results in multiple formats suitable for different use cases — from CI/CD pipelines to auditor verification.

---

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       ESP Agent                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Discovery  │───▶│   Scanner   │───▶│   Output    │     │
│  │             │    │             │    │             │     │
│  │ Find .esp   │    │ Compile     │    │ Format      │     │
│  │ files       │    │ Collect     │    │ Results     │     │
│  │             │    │ Validate    │    │             │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                            │                   │            │
│                            ▼                   ▼            │
│                     ┌───────────┐       ┌───────────┐      │
│                     │ Registry  │       │  Console  │      │
│                     │           │       │  + File   │      │
│                     │ CTN Types │       │  Output   │      │
│                     └───────────┘       └───────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### From Source

```bash
# Build the agent
cargo build --release

# Install to ~/.cargo/bin
cargo install --path .
```

### Using Makefile

```bash
make build      # Debug build
make release    # Release build
```

---

## Usage

### Make (recommended)

```bash
make run ESP=../esp/policy.esp
make run-summary ESP=../esp/policy.esp
make run-attestation ESP=../esp/policy.esp
make run-full ESP=../esp/policy.esp
make run-assessor ESP=../esp/ksi_cna_mat_iam_mfa_elp_r9_auth_hardening.esp
make run-batch ESP=../esp/
```

### Direct Binary

```bash
# Scan a single policy file (console output only)
esp_agent policy.esp

# Scan all ESP files in a directory
esp_agent /path/to/policies/

# Save results to a file
esp_agent --output results.json policy.esp

# Specify output format
esp_agent --format attestation --output attestation.json policy.esp

# Quiet mode (file output only, no console)
esp_agent --quiet --output results.json /path/to/policies/
```

### Command-Line Options

```
USAGE:
    esp_agent [OPTIONS] <file.esp>       Scan single ESP file
    esp_agent [OPTIONS] <directory>      Scan all ESP files in directory

OPTIONS:
    -h, --help                  Show help message
    -q, --quiet                 Suppress console output
    -o, --output <file>         Write results to JSON file (optional)
    -f, --format <format>       Output format: full (default), summary,
                                attestation, assessor
```

---

## Output Formats

The agent produces a **single envelope** containing all scanned policies, regardless of how many ESP files were scanned.

| Format | Description | Use Case |
|--------|-------------|----------|
| `full` | Complete results with findings and evidence (default) | Remediation, incident response |
| `summary` | Minimal output with pass/fail counts | CI/CD pipelines, quick checks |
| `attestation` | CUI-free format safe for network transport | SIEM/SOAR, dashboards, SaaS |
| `assessor` | Full package with reproducibility info | Auditor verification, 3PAO |

### Output Content Matrix

| Content | Summary | Attestation | Full | Assessor |
|---------|---------|-------------|------|----------|
| Policy ID | ✓ | ✓ | ✓ | ✓ |
| Outcome (pass/fail) | ✓ | ✓ | ✓ | ✓ |
| Criticality | ✓ | ✓ | ✓ | ✓ |
| Criteria counts | ✓ | ✗ | ✗ | ✗ |
| Control mappings | ✗ | ✓ | ✓ | ✓ |
| Weight | ✗ | ✓ | ✓ | ✓ |
| Replay hash | ✗ | ✓ | ✓ | ✓ |
| Host ID | ✗ | ✓ | ✓ | ✓ |
| Signature block | ✗ | ✓ | ✓ | ✓ |
| Findings | ✗ | ✗ | ✓ | ✓ |
| Evidence data | ✗ | ✗ | ✓ | ✓ |
| Collection method | ✗ | ✗ | ✓ | ✓ |
| Reproducibility info | ✗ | ✗ | ✗ | ✓ |

### Network Safety

| Format | Contains CUI | Network Safe |
|--------|--------------|--------------|
| Summary | No | Yes |
| Attestation | No | Yes |
| Full Results | Yes | No |
| Assessor Package | Yes | No |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All policies passed |
| 1 | One or more policies failed |
| 2 | Execution error |

---

## Architecture

### Module Structure

```
agent/
├── src/
│   ├── main.rs              # Entry point, CLI orchestration
│   ├── cli.rs               # Argument parsing
│   ├── config.rs            # ScanConfig, OutputFormat
│   ├── discovery.rs         # ESP file discovery
│   ├── registry.rs          # CTN strategy registry setup
│   ├── scanner.rs           # Core scanning logic
│   ├── output/
│   │   ├── mod.rs           # Output coordination
│   │   ├── console.rs       # Console formatting
│   │   ├── summary.rs       # Summary JSON builder
│   │   ├── attestation.rs   # Attestation builder
│   │   ├── full.rs          # Full result builder
│   │   └── assessor.rs      # Assessor package builder
│   └── contract_kit/        # CTN collectors, executors, contracts
│       ├── collectors/      # System data collectors
│       ├── executors/       # State validation executors
│       ├── contracts/       # CTN contract definitions
│       ├── commands/        # Shell command wrappers
│       └── execution_api.rs # High-level scan API
├── Cargo.toml
├── Makefile
└── rust-toolchain.toml
```

See the [Contract Development Guide](../guides/Contract_Development_Guide.md) for adding new CTN types, and the [ESP Language Guide](../guides/ESP_Language_Guide.md) for writing policies.

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ESP_LOGGING_MIN_LEVEL` | Minimum log level | `info` |
| `ESP_LOGGING_USE_STRUCTURED` | Enable JSON logging | `false` |
| `ESP_LOGGING_CARGO_STYLE` | Cargo-style error output | `true` |

```bash
export ESP_LOGGING_MIN_LEVEL=debug
esp_agent policy.esp
```

---

## Console Output

```
ESP Compliance Agent v0.1.0
Scanning 3 ESP file(s)...

[1/3] ✓ test-file-metadata-001 (3/3 criteria)
[2/3] ✓ test-file-content-001 (4/4 criteria)
[3/3] ✗ test-tcp-listener-001 (2 findings)
       └─ FINDING-001: Port 2024 not listening

╔═══════════════════════════════════════════════════════════════════════════════╗
║                                 SUMMARY                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║   Total Policies:   3   Passed: 2   Failed: 1                                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║   Posture Score:  85.0%                                                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

## License

Apache 2.0
