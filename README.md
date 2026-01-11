# ESP Windows Reference Implementation

A compliance scanning agent that executes ESP (Endpoint State Policy) files to validate system configurations against security policies.

## Quick Start

### Download Pre-built Binary (Windows)

1. Download the latest `esp_agent.exe` from the releases
2. Place it in your working directory
3. Run a scan:

```powershell
# Scan a single policy file
.\esp_agent.exe policy.esp

# Scan all policies in a directory
.\esp_agent.exe .\policies\

# Save results to a file
.\esp_agent.exe --output results.json policy.esp
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/scanset/Windows-Reference-Implementation.git
cd Windows-Reference-Implementation

# Build Windows release binary (copies to project root)
make release-win

# Binary is now available at ./esp_agent.exe
```

## Usage

```
esp_agent [OPTIONS] <file.esp|directory>

OPTIONS:
    -h, --help                  Show help message
    -q, --quiet                 Suppress console output
    -o, --output <file>         Write results to JSON file
    -f, --format <format>       Output format (see below)

OUTPUT FORMATS:
    full          Complete results with findings and evidence (default)
    summary       Minimal output with pass/fail counts only
    attestation   CUI-free format safe for network transport
    assessor      Full package with reproducibility info

EXIT CODES:
    0    All policies passed
    1    One or more policies failed
    2    Execution error
```

### Examples

```powershell
# Console output only (default)
.\esp_agent.exe policy.esp

# Save full results to JSON
.\esp_agent.exe --output results.json policy.esp

# Generate attestation (no sensitive data, safe for network)
.\esp_agent.exe --format attestation --output attestation.json policy.esp

# Generate assessor package (includes reproducibility info)
.\esp_agent.exe --format assessor --output assessor_package.json policy.esp

# Quiet mode - file output only, no console
.\esp_agent.exe --quiet --output results.json policy.esp

# Batch scan all ESP files in a directory
.\esp_agent.exe --format full --output batch_results.json .\policies\
```

## Policy Library

A growing collection of pre-built ESP policies for common compliance frameworks is available at:

**[github.com/scanset/Policy-Library](https://github.com/scanset/Policy-Library)**

The policy library includes:
- **DISA STIG** - Windows 11, Server 2022, and more
- **CIS Benchmarks** - Windows, Linux hardening
- **Custom Policies** - Malware detection, configuration audits

```powershell
# Clone the policy library
git clone https://github.com/scanset/Policy-Library.git

# Run all Windows STIG policies
.\esp_agent.exe --output stig_results.json .\Policy-Library\windows\stig\
```

## Supported CTN Types

| CTN Type | Description | Platform | Reference |
|----------|-------------|----------|-----------|
| `registry` | Windows Registry key/value validation | Windows | [docs](contract_kit/docs/ctn_registry.md) |
| `registry_subkeys` | Registry subkey enumeration and counting | Windows | [docs](contract_kit/docs/ctn_registry_subkeys.md) |
| `file_metadata` | File permissions, ownership, attributes | All | [docs](contract_kit/docs/ctn_file_metadata.md) |
| `file_content` | File content validation (contains, pattern match) | All | [docs](contract_kit/docs/ctn_file_content.md) |
| `json_record` | Structured JSON file validation with path queries | All | [docs](contract_kit/docs/ctn_json_record.md) |
| `tcp_listener` | TCP port listening validation | Linux | [docs](contract_kit/docs/ctn_tcp_listener.md) |
| `computed_values` | Validate RUN operation results (testing only) | All | [docs](contract_kit/docs/ctn_computed_values.md) |

### Common Windows SIDs

| SID | Name |
|-----|------|
| `S-1-5-18` | Local System |
| `S-1-5-19` | Local Service |
| `S-1-5-20` | Network Service |
| `S-1-5-32-544` | Administrators |
| `S-1-5-32-545` | Users |
| `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` | TrustedInstaller |

## ESP File Format

ESP files define compliance policies using a declarative syntax:

```esp
# Check Windows hosts file is protected
META
    esp_id `win-hosts-protected`
    version `1.0.0`
    title `Hosts file must be system-owned`
    platform `windows`
    criticality `high`
META_END

DEF
    OBJECT hosts_file
        path `C:\Windows\System32\drivers\etc\hosts`
    OBJECT_END

    STATE system_owned
        exists boolean = true
        readable boolean = true
        owner_id string = `S-1-5-18`
    STATE_END

    CRI AND
        CTN file_metadata
            TEST at_least_one all
            STATE_REF system_owned
            OBJECT_REF hosts_file
        CTN_END
    CRI_END
DEF_END
```

## Development

### Prerequisites

- Rust 1.85+ with cross-compilation targets
- For Windows builds from Linux: `mingw-w64`

```bash
# Install Windows cross-compilation target
rustup target add x86_64-pc-windows-gnu

# Install cross-compiler (Ubuntu/Debian)
sudo apt install mingw-w64
```

### Makefile Commands

```bash
# Build
make build              # Debug build (native)
make release            # Release build (native)
make build-win          # Debug build (Windows)
make release-win        # Release build (Windows) → ./esp_agent.exe

# Test
make test               # Run all tests
make test-win           # Compile tests for Windows

# Quality
make lint               # Run clippy (strict)
make lint-win           # Lint Windows target
make format             # Format code

# CI
make pre-commit         # Format check + lint + test
make ci                 # Full CI pipeline (all targets)
```

### Build All Targets

```bash
# Build for all platforms
make release-all

# Outputs:
#   target/release/esp_agent                           (Linux)
#   target/x86_64-pc-windows-gnu/release/esp_agent.exe (Windows)
#   target/x86_64-unknown-linux-musl/release/esp_agent (Linux static)
```

## Output Formats

### Full Results (default)

Complete results including findings, evidence, and collection details.

```json
{
  "envelope": {
    "format_version": "1.0.0",
    "content_hash": "sha256:...",
    "evidence_hash": "sha256:...",
    "signature": { ... }
  },
  "summary": { ... },
  "policies": [
    {
      "identity": { "policy_id": "win-hosts-protected", ... },
      "outcome": "pass",
      "findings": [],
      "evidence": { ... }
    }
  ]
}
```

### Attestation

CUI-free format safe for network transport. No sensitive evidence data.

```json
{
  "envelope": { ... },
  "summary": { ... },
  "checks": [
    {
      "identity": { "policy_id": "win-hosts-protected", ... },
      "outcome": "pass",
      "weight": 1.0
    }
  ]
}
```

### Assessor Package

Full results plus reproducibility information for third-party assessors.

```json
{
  "envelope": { ... },
  "package_info": { ... },
  "reproducibility": {
    "collection_commands": [ ... ],
    "environment": { ... }
  },
  "policies": [ ... ]
}
```

## Result Signing

All output formats (except `summary`) include cryptographic signatures in the result envelope for integrity verification and non-repudiation.

### Signature Block

```json
{
  "envelope": {
    "content_hash": "sha256:4be04373c38e7f9b...",
    "evidence_hash": "sha256:a3ad7521c85cacba...",
    "signature": {
      "signer_id": "tpm:sha256:94dbe9e6e942b829",
      "signer_type": "agent",
      "algorithm": "tpm-ecdsa-p256",
      "public_key": "ECS1...",
      "signature": "7eWJpNFv95Kd...",
      "key_id": "tpm:ephemeral:ESP_EPHEMERAL_...",
      "signed_at": "2026-01-25T18:39:43Z",
      "covers": ["content_hash", "evidence_hash"]
    }
  }
}
```

### Signing Methods

| Method | Description | Platform |
|--------|-------------|----------|
| `tpm-ecdsa-p256` | TPM 2.0 hardware-backed ECDSA | Windows (with TPM) |
| `software-ecdsa-p256` | Software ECDSA fallback | All |

### Hash Coverage

- **`content_hash`**: Covers policy definitions, criteria, and structural content
- **`evidence_hash`**: Covers collected evidence data and collection metadata

Both hashes are signed together, binding the policy evaluation to the evidence that produced it.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ESP Agent                             │
├─────────────────────────────────────────────────────────────┤
│  CLI Parser → Config → Scanner → Output Builder → Results   │
├─────────────────────────────────────────────────────────────┤
│                      contract_kit                            │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │  Compiler   │→ │  Execution   │→ │    Collectors     │   │
│  │  (ESP→AST)  │  │   Engine     │  │ (Registry, File)  │   │
│  └─────────────┘  └──────────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## License

Apache 2.0
