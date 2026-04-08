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
	@echo "  make release-win      - Build for Windows (release)"
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
	cargo build
dev:
	ESP_BUILD_PROFILE=development cargo build
release:
	ESP_BUILD_PROFILE=production cargo build --release

# =============================================================================
# Windows Cross-Compilation
# =============================================================================

build-win:
	cargo build --target $(WIN_TARGET)
	@echo ""
	@echo "Windows binaries built at: $(WIN_DEBUG_OUT)/"

release-win:
	ESP_BUILD_PROFILE=production cargo build --target $(WIN_TARGET) --release
	@echo ""
	@echo "Windows release binaries built at: $(WIN_RELEASE_OUT)/"

check-win:
	cargo check --target $(WIN_TARGET) --all-features

lint-win:
	cargo clippy --target $(WIN_TARGET) --all-targets --all-features -- $(CLIPPY_FLAGS)

test-win:
	cargo test --target $(WIN_TARGET)

# =============================================================================
# Linux musl Cross-Compilation (Static Builds)
# =============================================================================

build-musl:
	cargo build --target $(LINUX_MUSL_TARGET)
	@echo ""
	@echo "Linux musl binaries built at: $(MUSL_DEBUG_OUT)/"

release-musl:
	ESP_BUILD_PROFILE=production cargo build --target $(LINUX_MUSL_TARGET) --release
	@echo ""
	@echo "Linux musl release binaries built at: $(MUSL_RELEASE_OUT)/"

check-musl:
	cargo check --target $(LINUX_MUSL_TARGET) --all-features

lint-musl:
	cargo clippy --target $(LINUX_MUSL_TARGET) --all-targets --all-features -- $(CLIPPY_FLAGS)

# =============================================================================
# Linux GNU Cross-Compilation
# =============================================================================

build-linux:
	cargo build --target $(LINUX_GNU_TARGET)
	@echo ""
	@echo "Linux GNU binaries built at: $(LINUX_DEBUG_OUT)/"

release-linux:
	ESP_BUILD_PROFILE=production cargo build --target $(LINUX_GNU_TARGET) --release
	@echo ""
	@echo "Linux GNU release binaries built at: $(LINUX_RELEASE_OUT)/"

# =============================================================================
# Build All Targets
# =============================================================================

build-all: build build-win build-musl
	@echo ""
	@echo "All targets built successfully"

release-all: release release-win release-musl
	@echo ""
	@echo "All release targets built successfully"

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
	cargo run -- $(ESP) $(ARGS)

# Run with summary output format
run-summary:
ifndef ESP
	@echo "Usage: make run-summary ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run -- $(ESP) --format summary --output summary.json $(ARGS)

# Run with attestation output format
run-attestation:
ifndef ESP
	@echo "Usage: make run-attestation ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run -- $(ESP) --format attestation --output attestation.json $(ARGS)

# Run with full results output format
run-full:
ifndef ESP
	@echo "Usage: make run-full ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run -- $(ESP) --format full --output results.json $(ARGS)

# Run with assessor package output format
run-assessor:
ifndef ESP
	@echo "Usage: make run-assessor ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run -- $(ESP) --format assessor --output assessor_package.json $(ARGS)

# Run batch processing with full results
run-batch:
ifndef ESP
	@echo "Usage: make run-batch ESP=<directory>"
	@exit 1
endif
	cargo run -- $(ESP) --format full --output batch-output.json $(ARGS)

# Run in release mode
run-release:
ifndef ESP
	@echo "Usage: make run-release ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --release -- $(ESP) $(ARGS)

# =============================================================================
# Testing
# =============================================================================

test:
	ESP_BUILD_PROFILE=testing cargo test
test-unit:
	cargo test --lib

test-doc:
	cargo test --doc

test-agent:
	cargo test

# =============================================================================
# Code Quality
# =============================================================================

check:
	cargo check --all-targets --all-features

check-all: check check-win check-musl
	@echo "All targets check passed"

# Strict linting (CI/pre-commit)
lint:
	cargo clippy --all-targets --all-features -- $(CLIPPY_FLAGS)

# Quick linting (development)
lint-quick:
	cargo clippy --all-targets -- -D warnings

# Lint all targets
lint-all: lint lint-win lint-musl
	@echo "All targets lint passed"

# Auto-fix linting issues
lint-fix:
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

format:
	cargo fmt

format-check:
	cargo fmt -- --check

# =============================================================================
# Security
# =============================================================================

security: audit deny

audit:
	cargo audit

deny:
	@echo "Note: cargo-deny requires Rust 1.92+"
	@which cargo-deny > /dev/null && cargo deny check || \
		echo "cargo-deny not found. Install with: cargo install cargo-deny"

# =============================================================================
# Documentation
# =============================================================================

docs:
	cargo doc --all-features --no-deps --open

docs-all:
	cargo doc --all-features --document-private-items

# =============================================================================
# Docker Build
# =============================================================================

docker-build:
	docker build -f ../.devcontainer/Dockerfile -t $(AGENT_IMAGE) ..

# =============================================================================
# Cleaning
# =============================================================================

clean:
	cargo clean

clean-win:
	rm -rf target/$(WIN_TARGET)

clean-musl:
	rm -rf target/$(LINUX_MUSL_TARGET)

clean-all: clean
	rm -rf target/

# =============================================================================
# Pre-commit & CI
# =============================================================================

pre-commit: format-check lint test
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
	@ls -la .cargo/config.toml 2>/dev/null || echo "No .cargo/config.toml found"

# =============================================================================
# Dependency Management
# =============================================================================

outdated:
	cargo outdated
tree:
	cargo tree
bloat:
	cargo bloat --release --crates

# =============================================================================
# Installation
# =============================================================================

# Install agent binary to ~/.cargo/bin
install:
	cargo install --path .

# Install development tools
install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# =============================================================================
# Watch Mode (requires cargo-watch)
# =============================================================================

watch:
	cargo watch -x 'check'

watch-test:
	cargo watch -x 'test'

watch-win:
	cargo watch -x 'check --target $(WIN_TARGET)'

# =============================================================================
# Benchmarking
# =============================================================================

bench:
	cargo bench
