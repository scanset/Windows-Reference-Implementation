# ESP Agent SDK - Rust Development Container
# Cross-Compilation Support: Linux GNU, Linux musl, Windows GNU
# Security-focused development environment

FROM rust:1.85-bookworm

WORKDIR /workspace

# Environment variables for Rust tooling
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_BACKTRACE=1 \
    CARGO_INCREMENTAL=1

# Install system dependencies for all cross-compilation targets
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    pkg-config \
    libssl-dev \
    # Windows cross-compilation (MinGW-w64)
    gcc-mingw-w64-x86-64 \
    g++-mingw-w64-x86-64 \
    # Linux musl cross-compilation (static builds for RHEL, Alpine, etc.)
    musl-tools \
    musl-dev \
    # Development tools
    git \
    curl \
    # Debugging tools
    gdb \
    lldb \
    # Utilities
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain components
RUN rustup component add \
    clippy \
    rustfmt \
    rust-src \
    rust-analyzer \
    llvm-tools-preview

# Add all cross-compilation targets
RUN rustup target add \
    x86_64-pc-windows-gnu \
    x86_64-unknown-linux-gnu \
    x86_64-unknown-linux-musl

# Install security-focused cargo tools
RUN cargo install --locked cargo-audit && \
    cargo install --locked cargo-deny@0.18.3

# Git configuration defaults
RUN git config --global init.defaultBranch main && \
    git config --global core.autocrlf input && \
    git config --global pull.rebase false

# Note: Cargo cross-compilation config is in workspace .cargo/config.toml
# The workspace config.toml defines linker settings for each target

CMD ["/bin/bash"]
