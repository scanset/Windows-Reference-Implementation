# ESP Agent SDK Makefile
# Development, testing, and building commands
# Cross-Compilation Support: Linux GNU, Linux musl, Windows GNU

.PHONY: help build build-all test lint clean check security audit format docs dev release \
        run run-summary run-attestation run-full run-assessor run-batch run-release \
        build-win release-win check-win lint-win test-win \
        build-musl release-musl check-musl lint-musl \
        build-linux release-linux \
        pre-commit ci docker-build toolchain-info

# Default target
help:
	@echo "ESP Agent SDK - Available Commands"
	@echo "==================================="
	@echo ""
	@echo "Building (Native):"
	@echo "  make build            - Build agent (debug)"
	@echo "  make release          - Build agent (release)"
	@echo "  make dev              - Build in development mode"
	@echo "  make clean            - Clean all build artifacts"
	@echo ""
	@echo "Cross-Compilation - Windows:"
	@echo "  make build-win        - Build for Windows (debug)"
	@echo "  make release-win      - Build for Windows (release) → ./esp_agent.exe"
	@echo "  make check-win        - Check compilation for Windows"
	@echo "  make lint-win         - Run clippy for Windows target"
	@echo "  make test-win         - Run tests for Windows target"
	@echo ""
	@echo "Cross-Compilation - Linux musl (static):"
	@echo "  make build-musl       - Build for Linux musl (debug)"
	@echo "  make release-musl     - Build for Linux musl (release)"
	@echo "  make check-musl       - Check compilation for Linux musl"
	@echo "  make lint-musl        - Run clippy for Linux musl target"
	@echo ""
	@echo "Cross-Compilation - Linux GNU:"
	@echo "  make build-linux      - Build for Linux GNU (debug)"
	@echo "  make release-linux    - Build for Linux GNU (release)"
	@echo ""
	@echo "Build All Targets:"
	@echo "  make build-all        - Build all targets (debug)"
	@echo "  make release-all      - Build all targets (release)"
	@echo ""
	@echo "Running:"
	@echo "  make run ESP=<file>              - Run agent (console only)"
	@echo "  make run-summary ESP=<file>      - Run with summary output"
	@echo "  make run-attestation ESP=<file>  - Run with attestation output"
	@echo "  make run-full ESP=<file>         - Run with full results output"
	@echo "  make run-assessor ESP=<file>     - Run with assessor package output"
	@echo "  make run-batch ESP=<dir>         - Batch run with full results"
	@echo "  make run-release ESP=<file>      - Run in release mode"
	@echo ""
	@echo "Testing:"
	@echo "  make test             - Run all tests"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-doc         - Run documentation tests"
	@echo "  make test-kit         - Run contract_kit tests"
	@echo "  make test-agent       - Run agent tests"
	@echo ""
	@echo "Quality:"
	@echo "  make check            - Quick compilation check"
	@echo "  make check-all        - Check all targets"
	@echo "  make lint             - Run clippy linter (strict)"
	@echo "  make lint-quick       - Run clippy linter (warnings only)"
	@echo "  make lint-all         - Lint all targets"
	@echo "  make format           - Format code with rustfmt"
	@echo "  make format-check     - Check code formatting"
	@echo ""
	@echo "Security:"
	@echo "  make security         - Run all security checks"
	@echo "  make audit            - Check for vulnerabilities"
	@echo "  make deny             - Check dependency policies"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     - Build development Docker image"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs             - Generate and open documentation"
	@echo "  make docs-all         - Generate all documentation"
	@echo ""
	@echo "Pre-commit & CI:"
	@echo "  make pre-commit       - Run pre-commit checks"
	@echo "  make ci               - Run full CI checks (all targets)"
	@echo ""
	@echo "Utilities:"
	@echo "  make toolchain-info   - Show Rust toolchain information"
	@echo "  make outdated         - Check for outdated dependencies"
	@echo "  make tree             - Show dependency tree"
	@echo ""
	@echo "Examples:"
	@echo "  make run ESP=policy.esp"
	@echo "  make run-full ESP=policy.esp"
	@echo "  make run-batch ESP=/path/to/policies/"
	@echo "  make release-win      # Builds and copies esp_agent.exe to project root"
	@echo "  make release-all"
	@echo ""

# =============================================================================
# Variables
# =============================================================================

# Docker image
IMAGE_NAME := esp-agent
IMAGE_TAG := v1
AGENT_IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)

# Cross-compilation targets
WIN_TARGET := x86_64-pc-windows-gnu
LINUX_GNU_TARGET := x86_64-unknown-linux-gnu
LINUX_MUSL_TARGET := x86_64-unknown-linux-musl

# Output directories
WIN_DEBUG_OUT := target/$(WIN_TARGET)/debug
WIN_RELEASE_OUT := target/$(WIN_TARGET)/release
MUSL_DEBUG_OUT := target/$(LINUX_MUSL_TARGET)/debug
MUSL_RELEASE_OUT := target/$(LINUX_MUSL_TARGET)/release
LINUX_DEBUG_OUT := target/$(LINUX_GNU_TARGET)/debug
LINUX_RELEASE_OUT := target/$(LINUX_GNU_TARGET)/release

# Clippy flags (strict)
CLIPPY_FLAGS := -D warnings \
	-D clippy::unwrap_used \
	-D clippy::expect_used \
	-D clippy::panic \
	-D clippy::indexing_slicing

# =============================================================================
# Native Builds
# =============================================================================

build:
	cargo build --workspace

dev:
	ESP_BUILD_PROFILE=development cargo build --package agent

release:
	ESP_BUILD_PROFILE=production cargo build --release --workspace

# =============================================================================
# Windows Cross-Compilation
# =============================================================================

build-win:
	cargo build --workspace --target $(WIN_TARGET)
	@echo ""
	@echo "Windows binaries built at: $(WIN_DEBUG_OUT)/"

release-win:
	ESP_BUILD_PROFILE=production cargo build --workspace --target $(WIN_TARGET) --release
	@cp $(WIN_RELEASE_OUT)/esp_agent.exe ./esp_agent.exe
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  Windows release binary ready: ./esp_agent.exe"
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  Quick start:"
	@echo "    Copy esp_agent.exe to your Windows machine and run:"
	@echo ""
	@echo "    .\\esp_agent.exe policy.esp                    # Console output"
	@echo "    .\\esp_agent.exe --output results.json .\\ 	  # Scan directory"
	@echo "    .\\esp_agent.exe --format attestation -o a.json policy.esp"
	@echo ""

check-win:
	cargo check --workspace --target $(WIN_TARGET) --all-features

lint-win:
	cargo clippy --workspace --target $(WIN_TARGET) --all-targets --all-features -- $(CLIPPY_FLAGS)

test-win:
	cargo test --workspace --target $(WIN_TARGET) --all-features --no-run

# =============================================================================
# Linux musl Cross-Compilation (Static Builds)
# =============================================================================

build-musl:
	cargo build --workspace --target $(LINUX_MUSL_TARGET)
	@echo ""
	@echo "Linux musl binaries built at: $(MUSL_DEBUG_OUT)/"

release-musl:
	ESP_BUILD_PROFILE=production cargo build --workspace --target $(LINUX_MUSL_TARGET) --release
	@cp $(MUSL_RELEASE_OUT)/esp_agent ./esp_agent_musl
	@echo ""
	@echo "Linux musl release binary ready: ./esp_agent_musl"

check-musl:
	cargo check --workspace --target $(LINUX_MUSL_TARGET) --all-features

lint-musl:
	cargo clippy --workspace --target $(LINUX_MUSL_TARGET) --all-targets --all-features -- $(CLIPPY_FLAGS)

# =============================================================================
# Linux GNU Cross-Compilation
# =============================================================================

build-linux:
	cargo build --workspace --target $(LINUX_GNU_TARGET)
	@echo ""
	@echo "Linux GNU binaries built at: $(LINUX_DEBUG_OUT)/"

release-linux:
	ESP_BUILD_PROFILE=production cargo build --workspace --target $(LINUX_GNU_TARGET) --release
	@cp $(LINUX_RELEASE_OUT)/esp_agent ./esp_agent_linux
	@echo ""
	@echo "Linux GNU release binary ready: ./esp_agent_linux"

# =============================================================================
# Build All Targets
# =============================================================================

build-all: build build-win build-musl
	@echo ""
	@echo "All targets built successfully"

release-all: release release-win release-musl
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════════"
	@echo "  All release binaries ready:"
	@echo "    ./esp_agent.exe    - Windows x86_64"
	@echo "    ./esp_agent_musl   - Linux x86_64 (static)"
	@echo "    ./esp_agent_linux  - Linux x86_64 (GNU)"
	@echo "═══════════════════════════════════════════════════════════════════"

# =============================================================================
# Running (Native Only)
# =============================================================================

# Run the agent (console output only)
run:
ifndef ESP
	@echo "Usage: make run ESP=<file.esp|directory>"
	@echo ""
	@echo "Examples:"
	@echo "  make run ESP=policy.esp"
	@echo "  make run ESP=/path/to/policies/"
	@exit 1
endif
	cargo run --package agent -- $(ESP) $(ARGS)

# Run with summary output format
run-summary:
ifndef ESP
	@echo "Usage: make run-summary ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --package agent -- $(ESP) --format summary --output summary.json $(ARGS)

# Run with attestation output format
run-attestation:
ifndef ESP
	@echo "Usage: make run-attestation ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --package agent -- $(ESP) --format attestation --output attestation.json $(ARGS)

# Run with full results output format
run-full:
ifndef ESP
	@echo "Usage: make run-full ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --package agent -- $(ESP) --format full --output results.json $(ARGS)

# Run with assessor package output format
run-assessor:
ifndef ESP
	@echo "Usage: make run-assessor ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --package agent -- $(ESP) --format assessor --output assessor_package.json $(ARGS)

# Run batch processing with full results
run-batch:
ifndef ESP
	@echo "Usage: make run-batch ESP=<directory>"
	@exit 1
endif
	cargo run --package agent -- $(ESP) --format full --output batch-output.json $(ARGS)

# Run in release mode
run-release:
ifndef ESP
	@echo "Usage: make run-release ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --release --package agent -- $(ESP) $(ARGS)

# =============================================================================
# Testing
# =============================================================================

test:
	ESP_BUILD_PROFILE=testing cargo test --workspace

test-unit:
	cargo test --workspace --lib

test-doc:
	cargo test --workspace --doc

test-kit:
	cargo test --package contract_kit

test-agent:
	cargo test --package agent

# =============================================================================
# Code Quality
# =============================================================================

check:
	cargo check --workspace --all-targets --all-features

check-all: check check-win check-musl
	@echo "All targets check passed"

# Strict linting (CI/pre-commit)
lint:
	cargo clippy --workspace --all-targets --all-features -- $(CLIPPY_FLAGS)

# Quick linting (development)
lint-quick:
	cargo clippy --workspace --all-targets -- -D warnings

# Lint all targets
lint-all: lint lint-win lint-musl
	@echo "All targets lint passed"

# Auto-fix linting issues
lint-fix:
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- -D warnings

format:
	cargo fmt --all

format-check:
	cargo fmt --all -- --check

# =============================================================================
# Security
# =============================================================================

security: audit deny

audit:
	cargo audit

deny:
	@echo "Note: cargo-deny requires Rust 1.85+"
	@which cargo-deny > /dev/null && cargo deny check || \
		echo "cargo-deny not found. Install with: cargo install cargo-deny"

# =============================================================================
# Documentation
# =============================================================================

docs:
	cargo doc --workspace --all-features --no-deps --open

docs-all:
	cargo doc --workspace --all-features --document-private-items

# =============================================================================
# Docker Build
# =============================================================================

docker-build:
	docker build -t $(AGENT_IMAGE) .

# =============================================================================
# Cleaning
# =============================================================================

clean:
	cargo clean
	rm -f esp_agent.exe esp_agent_musl esp_agent_linux

clean-win:
	rm -rf target/$(WIN_TARGET)
	rm -f esp_agent.exe

clean-musl:
	rm -rf target/$(LINUX_MUSL_TARGET)
	rm -f esp_agent_musl

clean-all: clean
	rm -rf target/

# =============================================================================
# Pre-commit & CI
# =============================================================================

pre-commit: format-check lint-win test
	@echo "✓ Pre-commit checks passed"

# Full CI check including all cross-compilation targets
ci: format-check lint-all check-all test security
	@echo "✓ CI checks passed"

# =============================================================================
# Tool Verification
# =============================================================================

toolchain-info:
	@echo "Rust toolchain information:"
	@rustup show
	@echo ""
	@echo "Installed targets:"
	@rustup target list --installed
	@echo ""
	@echo "Cargo config location:"
	@ls -la .cargo/config.toml 2>/dev/null || echo "No workspace .cargo/config.toml"

# =============================================================================
# Dependency Management
# =============================================================================

outdated:
	cargo outdated --workspace

tree:
	cargo tree --workspace

bloat:
	cargo bloat --release --crates

# =============================================================================
# Installation
# =============================================================================

# Install agent binary to ~/.cargo/bin
install:
	cargo install --path agent

# Install development tools
install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# =============================================================================
# Watch Mode (requires cargo-watch)
# =============================================================================

watch:
	cargo watch -x 'check --workspace'

watch-test:
	cargo watch -x 'test --workspace'

watch-win:
	cargo watch -x 'check --workspace --target $(WIN_TARGET)'

# =============================================================================
# Benchmarking
# =============================================================================

bench:
	cargo bench --workspace
