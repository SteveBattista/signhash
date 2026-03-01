# Makefile for SignHash development workflow

.PHONY: help dev test bench clean check release install lint format

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

dev: ## Fast development build with basic tests
	@./scripts/dev-build.sh

test: ## Run fast unit tests
	@./scripts/test.sh fast

test-all: ## Run all tests
	@./scripts/test.sh all

test-integration: ## Run integration tests only
	@./scripts/test.sh integration

bench: ## Run performance benchmarks
	@./scripts/bench.sh

clean: ## Clean build artifacts
	cargo clean

check: ## Fast syntax and type checking
	cargo check --all-targets

release: ## Build optimized release binaries
	cargo build --release

install: ## Install binaries to local system
	cargo install --path .

lint: ## Run clippy linter
	cargo clippy --all-targets --all-features -- -D warnings

format: ## Format code with rustfmt
	cargo fmt

format-check: ## Check if code is formatted
	cargo fmt -- --check

ci: ## Run CI pipeline locally (check, test, lint)
	make check
	make lint
	make test-all
	make format-check

# Development shortcuts
build: dev ## Alias for dev target

# Performance targets
perf: bench ## Alias for bench target

# Quick iteration cycle
quick: ## Super fast check for immediate feedback
	cargo check