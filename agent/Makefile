# ESP Agent SDK Makefile
# Development, testing, and building commands
# Cross-Compilation Support: Linux GNU, Linux musl, Windows GNU

.PHONY: help build build-all test lint clean check security audit deny sbom format docs dev release \
        run run-output run-batch run-release \
        build-win release-win check-win lint-win test-win \
        build-musl release-musl check-musl lint-musl \
        build-linux release-linux \
        pre-commit ready ci docker-build toolchain-info \
        install install-tools install-hooks

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
	@echo "  make run-output ESP=<file>       - Run + write signed AssessorPackage JSON"
	@echo "  make run-batch ESP=<dir>         - Batch run over a directory of policies"
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
	@echo "  make security         - audit + deny + sbom (full gate)"
	@echo "  make audit            - Check for vulnerabilities (cargo-audit)"
	@echo "  make deny             - Check dependency policies (cargo-deny)"
	@echo "  make sbom             - Generate CycloneDX SBOM under ../docs/sbom/"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build     - Build development Docker image"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs             - Generate and open documentation"
	@echo "  make docs-all         - Generate all documentation"
	@echo ""
	@echo "Pre-commit & CI:"
	@echo "  make install-hooks    - Install scripts/git-pre-commit into .git/hooks/"
	@echo "  make pre-commit       - Run pre-commit gate manually (fmt + lint + test)"
	@echo "  make ready            - format + sbom + lint + test (run before push)"
	@echo "  make ci               - Run full CI checks (all targets)"
	@echo ""
	@echo "Installation:"
	@echo "  make install          - Install esp_agent to ~/.cargo/bin"
	@echo "  make install-tools    - Install dev tools (cargo-audit, cargo-deny, cargo-cyclonedx, …)"
	@echo ""
	@echo "Utilities:"
	@echo "  make toolchain-info   - Show Rust toolchain information"
	@echo "  make outdated         - Check for outdated dependencies"
	@echo "  make tree             - Show dependency tree"
	@echo ""
	@echo "Examples:"
	@echo "  make run ESP=policy.esp"
	@echo "  make run-output ESP=policy.esp OUT=out.json"
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

# Run and write the signed AssessorPackage envelope to a JSON file.
# Override the filename via OUT=path/to/file.json; defaults to assessor_package.json.
OUT ?= assessor_package.json
run-output:
ifndef ESP
	@echo "Usage: make run-output ESP=<file.esp|directory> [OUT=path.json]"
	@exit 1
endif
	cargo run -- $(ESP) --output $(OUT) $(ARGS)

# Run over a directory of policies; one envelope per run.
run-batch:
ifndef ESP
	@echo "Usage: make run-batch ESP=<directory> [OUT=path.json]"
	@exit 1
endif
	cargo run -- $(ESP) --output $(OUT) $(ARGS)

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

# Full security gate: vulnerability scan + dependency policy + SBOM.
# Implements NIST SP 800-218 SSDF tasks PW.4.4 (verify components),
# PW.8.2 (automated vulnerability detection), PS.3.2 (component provenance).
security: audit deny sbom

audit:
	@which cargo-audit > /dev/null && cargo audit || \
		(echo "cargo-audit not found. Run: make install-tools" && exit 1)

deny:
	@which cargo-deny > /dev/null && cargo deny check || \
		(echo "cargo-deny not found. Run: make install-tools" && exit 1)

# Generate a CycloneDX SBOM for the agent crate, stage it under
# ../docs/sbom/, and canonicalize volatile fields (serialNumber, timestamp,
# absolute checkout paths) so the artifact is reproducible across machines.
# Implements NIST SP 800-218 SSDF PS.3.2 (provenance for components).
SBOM_OUT_DIR := ../docs/sbom
sbom:
	@which cargo-cyclonedx > /dev/null || \
		(echo "cargo-cyclonedx not found. Run: make install-tools" && exit 1)
	@command -v python3 > /dev/null || \
		(echo "python3 required for SBOM normalization" && exit 1)
	@mkdir -p $(SBOM_OUT_DIR)
	cargo cyclonedx --format json --spec-version 1.5 --quiet
	@find . -maxdepth 2 -name '*.cdx.json' -not -path './target/*' \
		-exec mv {} $(SBOM_OUT_DIR)/ \;
	python3 ../scripts/normalize_sbom.py $(SBOM_OUT_DIR)/*.cdx.json
	@echo "Generated (canonicalized) SBOMs:"
	@ls -1 $(SBOM_OUT_DIR)/*.cdx.json

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

# Manual pre-commit gate — the same checks the installed git hook runs.
# Install the hook with `make install-hooks` so this runs automatically.
pre-commit: format-check lint test
	@echo "✓ Pre-commit checks passed"

# Auto-fix everything that can be auto-fixed, then run the full gate.
# This is what to run locally before `git push` to mirror what CI will
# enforce. Order matters: format first (changes lines), then sbom
# (changes files), then lint + test against the canonicalized tree.
ready: format sbom lint test
	@echo ""
	@echo "✓ Ready to commit. Review changes with: git status"

# Full CI check including all cross-compilation targets
ci: format-check lint-all check-all test security
	@echo "✓ CI checks passed"

# Install the repository's pre-commit hook into .git/hooks/.
# Idempotent: re-running overwrites the existing hook. Any pre-existing
# hook is backed up to .git/hooks/pre-commit.bak so it's recoverable.
install-hooks:
	@if [ ! -d ../.git ]; then \
		echo "Not a git repository (../.git missing); nothing to install."; exit 1; \
	fi
	@if [ -f ../.git/hooks/pre-commit ] && [ ! -L ../.git/hooks/pre-commit ]; then \
		mv ../.git/hooks/pre-commit ../.git/hooks/pre-commit.bak; \
		echo "→ existing .git/hooks/pre-commit backed up to .bak"; \
	fi
	@cp ../scripts/git-pre-commit ../.git/hooks/pre-commit
	@chmod +x ../.git/hooks/pre-commit
	@echo "✓ Installed scripts/git-pre-commit → .git/hooks/pre-commit"
	@echo "  Skip the hook for an individual commit with: git commit --no-verify"

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

# Install development tools.
# Security/SBOM tooling supports NIST SP 800-218 SSDF compliance:
#   cargo-audit       - PW.8.2 / RV.1.1 vulnerability scanning
#   cargo-deny        - PS.3.2 / PW.4.4 license + source verification
#   cargo-cyclonedx   - PS.3.2 SBOM generation (CycloneDX)
install-tools:
	cargo install --locked cargo-audit cargo-deny cargo-cyclonedx \
		cargo-outdated cargo-watch cargo-tree cargo-bloat

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
