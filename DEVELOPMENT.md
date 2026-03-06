# Developer Workflow Guide

This document outlines optimized workflows for faster development on SignHash.

## ⚡ Quick Start

```bash
# Clone and setup
git clone <repo>
cd signhash

# Install development dependencies (optional but recommended)
cargo install cargo-watch criterion-compare

# Quick development cycle
make quick          # Super fast syntax/type check (< 5s)
make dev           # Fast development build + basic tests (< 30s) 
make test          # Run fast unit tests only (< 10s)
make bench         # Run performance benchmarks
```

## 🚀 Development Profiles

We have optimized build profiles for different scenarios:

- `cargo check` - Fastest feedback (syntax/type check only)
- `cargo build --profile dev-opt` - Fast builds with some optimization  
- `cargo build --release` - Full optimization for performance testing

## 🔄 Continuous Development with Watch Mode

For live reloading during development:

```bash
# Watch for changes and run quick checks
cargo watch -x check

# Watch and run tests on changes  
cargo watch -x 'test --lib'

# Watch and rebuild + test
cargo watch -x 'build --profile dev-opt' -x 'test --lib'
```

## 📊 Performance Monitoring

Run benchmarks to track performance:

```bash
make bench                   # Run all benchmarks
cargo bench --bench performance -- blake3   # Test specific algorithm
```

View detailed benchmark reports at `target/criterion/report/index.html`

## 🧪 Smart Testing

Use targeted test runs for faster feedback:

```bash
./scripts/test.sh fast        # Unit tests only (~1s)
./scripts/test.sh hash        # Hash-related tests only
./scripts/test.sh crypto      # Crypto-related tests only  
./scripts/test.sh integration # Integration tests only
./scripts/test.sh all         # Full test suite (289 tests)
```

## 💡 IDE Integration

### VS Code

Open the workspace file for optimized settings:

```bash
code signhash.code-workspace
```

Key shortcuts:

- `Ctrl+Shift+P` → "Tasks: Run Task" → "Quick Check" for fast validation
- `Ctrl+Shift+P` → "Tasks: Run Task" → "Dev Build" for development build
- `F5` to debug with sample data

### Rust Analyzer

The workspace is configured with:

- Fast incremental compilation
- Optimized file watching (excludes target/ directory)
- Auto-formatting on save
- Integrated clippy linting

## 🐛 Debugging

### Performance Debugging

```bash
# Profile a specific algorithm
cargo build --release
perf record ./target/release/sign_hash -d large_test_dir -a blake3
perf report

# Memory usage analysis  
valgrind --tool=massif ./target/release/sign_hash -d test_dir
```

### Test Debugging

```bash
# Run specific test with output
cargo test test_name -- --nocapture

# Debug test with gdb/lldb
rust-gdb target/debug/deps/test_binary
```

## 📈 Performance Tips

1. **Use BLAKE3** for fastest hashing (5-10x faster than SHA256)
2. **Memory mapping** is automatically used for files ≥16KB  
3. **Parallel processing** scales automatically with CPU cores
4. **Release builds** are ~10x faster than debug builds

## 🔧 Troubleshooting

### Slow Builds?

```bash
# Clear incremental compilation cache if corrupt
rm -rf target/debug/incremental target/release/incremental

# Check compilation bottlenecks
cargo build --timings
```

### Test Failures?

```bash
# Run with verbose output
cargo test -- --nocapture

# Single threaded testing (avoid race conditions)
cargo test -- --test-threads=1
```

## 📋 Pre-commit Checklist

Before pushing changes:

```bash
make ci    # Runs check, lint, test-all, format-check
```

Or manually:

1. `make check` - Fast syntax/type validation
2. `make lint` - Clippy linting (pedantic compliance)
3. `make test-all` - Full test suite (289 tests)
4. `make format-check` - Code formatting validation
5. `make bench` - Performance regression check (if relevant)

### Quality Standards

- ✅ All 289 tests passing
- ✅ Zero clippy::pedantic warnings
- ✅ Modern Rust idioms (yaml-rust2, inline format strings)
- ✅ Comprehensive documentation with examples

Licensed under the MIT License. Copyright 2026 MITRE | #26-0488 03/06/26
