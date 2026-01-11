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
cargo build --release --package agent

# Install to ~/.cargo/bin
cargo install --path agent
```

### Using Makefile

```bash
# Build the agent
make build

# Build release version
make release
```

---

## Usage

### Basic Commands

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
    esp_agent --help                     Show help message

OPTIONS:
    -h, --help                  Show help message
    -q, --quiet                 Suppress console output
    -o, --output <file>         Write results to JSON file (optional)
    -f, --format <format>       Output format: full (default), summary,
                                attestation, assessor
```

### Examples

```bash
# Console output only
esp_agent policy.esp

# Console + file output
esp_agent --output results.json policy.esp

# Attestation format to file
esp_agent --format attestation -o attestation.json policy.esp

# Batch scan, file only, no console
esp_agent --quiet -o results.json /path/to/policies/

# Assessor package for audit
esp_agent --format assessor -o assessor_package.json /path/to/policies/
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
| Evidence hash | ✗ | ✓ | ✓ | ✓ |
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
│   ├── main.rs          # Entry point, CLI orchestration
│   ├── cli.rs           # Argument parsing, help text
│   ├── config.rs        # Configuration types (ScanConfig, OutputFormat)
│   ├── discovery.rs     # ESP file discovery
│   ├── registry.rs      # CTN strategy registry setup
│   ├── scanner.rs       # Core scanning logic
│   └── output/
│       ├── mod.rs       # Output module coordination
│       ├── console.rs   # Console formatting
│       ├── summary.rs   # Summary JSON builder
│       ├── attestation.rs # Attestation builder
│       ├── full.rs      # Full result builder
│       └── assessor.rs  # Assessor package builder
└── Cargo.toml
```

### Processing Pipeline

```
1. CLI Parsing
   └── Parse arguments → ScanConfig

2. Discovery
   └── Find .esp files in path

3. Registry Setup
   └── Create CTN strategy registry with collectors/executors

4. Scanning (per file)
   ├── Compile ESP file
   ├── Collect system data
   ├── Validate against states
   └── Generate findings

5. Output
   ├── Print to console (unless --quiet)
   └── Write to file (if --output specified)
```

### Registered CTN Types

The agent registers the following CTN strategies:

| CTN Type | Collector | Executor |
|----------|-----------|----------|
| `file_metadata` | FileSystemCollector | FileMetadataExecutor |
| `file_content` | FileSystemCollector | FileContentExecutor |
| `json_record` | FileSystemCollector | JsonRecordExecutor |
| `tcp_listener` | TcpListenerCollector | TcpListenerExecutor |
| `k8s_resource` | K8sResourceCollector | K8sResourceExecutor |
| `computed_values` | ComputedValuesCollector | ComputedValuesExecutor |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ESP_LOGGING_MIN_LEVEL` | Minimum log level | `info` |
| `ESP_LOGGING_USE_STRUCTURED` | Enable JSON logging | `false` |
| `ESP_LOGGING_CARGO_STYLE` | Cargo-style error output | `true` |

### Logging Levels

| Level | What You See |
|-------|--------------|
| `debug` | Everything (tokens, symbols, validation steps) |
| `info` | Phase completions, scan results (default) |
| `warning` | Potential issues, non-critical problems |
| `error` | Only critical errors |

```bash
# Enable debug logging
export ESP_LOGGING_MIN_LEVEL=debug
esp_agent policy.esp
```

---

## Console Output

### Progress Output

During scanning, the agent displays progress:

```
ESP Compliance Agent v0.1.0
Scanning 3 ESP file(s)...

[1/3] ✓ test-file-metadata-001 (3/3 criteria)
[2/3] ✓ test-file-content-001 (4/4 criteria)
[3/3] ✗ test-tcp-listener-001 (2 findings)
       └─ FINDING-001: Port 2024 not listening
```

### Results Summary

After scanning, a summary is displayed:

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                 SUMMARY                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   Total Policies:   3                                                         ║
║   Passed:           2                                                         ║
║   Failed:           1                                                         ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║   Posture Score:  85.0%                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   By Criticality:        Pass    Fail    Total                                ║
║   ─────────────────────────────────────────                                   ║
║   High                     1       0        1                                 ║
║   Medium                   1       1        2                                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

### Posture Score

The posture score is a weighted average based on criticality:

| Criticality | Weight |
|-------------|--------|
| Critical | 1.0 |
| High | 0.8 |
| Medium | 0.5 |
| Low | 0.3 |
| Info | 0.1 |

```
Posture Score = (Sum of passed weights) / (Sum of all weights) × 100%
```

---

## Dependencies

### Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `common` | Shared types, results, logging |
| `compiler` | ESP policy compilation |
| `execution_engine` | Resolution and execution framework |
| `contract_kit` | CTN collectors, executors, contracts |

### External Dependencies

| Dependency | Purpose |
|------------|---------|
| `serde` / `serde_json` | JSON serialization |

---

## Development

### Building

```bash
# Debug build
cargo build --package agent

# Release build
cargo build --release --package agent

# Run tests
cargo test --package agent
```

### Running Locally

```bash
# Run with cargo
cargo run --package agent -- policy.esp

# Run with arguments
cargo run --package agent -- --format summary -o out.json /path/to/policies/
```

### Adding CTN Types

To add a new CTN type, update `registry.rs`:

```rust
// Create contract
let my_contract = contracts::create_my_ctn_contract();

// Register strategy
registry.register_ctn_strategy(
    Box::new(collectors::MyCollector::new()),
    Box::new(executors::MyExecutor::new(my_contract)),
)?;
```

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [ESP Language Guide](../guides/ESP_Language_Guide.md) | Policy authoring tutorial |
| [ESP Overview](https://github.com/scanset/Endpoint-State-Policy) | Language specification

---

## License

Apache 2.0
