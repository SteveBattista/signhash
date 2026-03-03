# Requirements

This document outlines the system, development, and runtime requirements for the SignHash project.

## 🦀 Rust Requirements

### Minimum Rust Version

- **Rust 1.70.0 or later** (recommended: latest stable)
- **Edition**: 2024
- **Target**: Cross-platform (Windows, macOS, Linux)

### Required Rust Features

- Standard library with threading support
- File system operations and memory mapping
- Cryptographic operations support

## 📦 Runtime Dependencies

### Core Dependencies

All dependencies are automatically managed by Cargo:

| Dependency     | Version              | Purpose                                              |
|----------------|----------------------|------------------------------------------------------|
| `ring`         | 0.17.14              | Ed25519 cryptographic signing and verification       |
| `data-encoding`| 2.10.0               | Hexadecimal encoding/decoding                        |
| `rayon`        | 1.8+                 | Multi-threaded parallel processing                   |
| `clap`         | 4.5.60+              | Command-line argument parsing                        |
| `serde`        | 1.0.117+             | Serialization framework                              |
| `yaml-rust2`   | 0.8+                 | YAML file format support for keys                   |
| `rand`         | 0.10.0               | Cryptographic random number generation               |
| `chrono`       | 0.4.44+              | Date and time handling                               |
| `indicatif`    | 0.18.4+              | Progress bar display                                 |
| `walkdir`      | 2.3.1+               | Recursive directory traversal                        |
| `log`          | 0.4.*                | Logging framework                                    |
| `blake3`       | 1.8.3+               | BLAKE3 hashing (with rayon and mmap features)        |
| `memmap2`      | 0.9.10+              | Memory-mapped file I/O (optional, default enabled)   |
| `anyhow`       | 1.0.102+             | Error handling                                       |

### Optional Features

- `memmap2` (default): Enables memory-mapped file I/O for performance
  - Provides zero-copy hashing for files ≥16KB
  - Falls back to streaming I/O when unavailable

## 🛠️ Development Dependencies

### Testing and Benchmarking

| Dependency  | Version | Purpose                                                   |
|-------------|---------|-----------------------------------------------------------|
| `tempfile`  | 3.26.0+ | Temporary files for testing                               |
| `criterion` | 0.8.2+  | Performance benchmarking framework (with HTML reports)    |

### Development Tools (Optional but Recommended)

```bash
# Performance monitoring
cargo install criterion-compare

# Live reloading during development
cargo install cargo-watch

# Code formatting (included in Rust)
rustfmt

# Linting (included in Rust)
clippy
```

## 💻 System Requirements

### Operating Systems

- **Linux**: All distributions with glibc 2.17+ or musl
- **macOS**: macOS 10.12 Sierra or later
- **Windows**: Windows 10 or later (x64)

### Hardware Requirements

#### Minimum Requirements

- **CPU**: Any 64-bit processor
- **RAM**: 1GB available memory
- **Storage**: 50MB for binaries, additional space for manifests

#### Recommended Requirements

- **CPU**: Multi-core processor (4+ cores for optimal performance)
- **RAM**: 4GB+ for processing large file sets
- **Storage**: SSD recommended for large directory operations

### System Capabilities Required

- **File System**:
  - Read/write access to target directories
  - Support for file metadata (size, timestamps)
  - Symlink support (optional, but detected)
- **Memory Mapping**:
  - Virtual memory support for large files
  - Address space for memory-mapped operations
- **Multi-threading**:
  - Thread creation and management
  - Work-stealing thread pool support

## 🏗️ Build Requirements

### Compilation

- **Cargo**: Latest version (included with Rust)
- **C Compiler**: Required for some dependencies (ring, blake3)
  - Linux: `gcc` or `clang`
  - macOS: Xcode Command Line Tools
  - Windows: MSVC or GNU toolchain

### Build Profiles

The project includes optimized build profiles:

- `dev`: Fast compilation with basic optimization
- `dev-opt`: Balanced compilation speed and performance
- `release`: Full optimization for production use

### Build Features

- **Link-Time Optimization (LTO)**: Enabled in release builds
- **Incremental Compilation**: Enabled for faster rebuilds
- **Debug Symbols**: Configurable per profile

## 🔧 Development Environment

### Required Tools

- **Git**: Version control
- **Make**: Build automation (optional, scripts available)
- **Shell**: Unix shell or PowerShell for scripts

### IDE/Editor Support

SignHash works with any Rust-compatible editor:

- **VS Code**: With rust-analyzer extension
- **IntelliJ IDEA**: With Rust plugin
- **Vim/Neovim**: With rust-analyzer LSP
- **Emacs**: With rust-analyzer

### Linting and Formatting

- **Clippy**: All code passes `clippy::pedantic` linting
- **Rustfmt**: Standard Rust formatting enforced
- **Documentation**: All public APIs documented with examples

## 🚀 Performance Considerations

### Threading

- **Default**: Uses all available CPU cores
- **Configurable**: Thread pool size adjustable via `-p` flag
- **Minimum**: Single-threaded operation supported

### Memory Usage

- **Base**: ~10MB for application
- **Per File**: Minimal memory overhead with streaming
- **Large Files**: Memory-mapped for efficiency (no loading into RAM)
- **Adaptive**: Buffer sizes scale with file sizes (64KB-4MB)

### File Size Limits

- **Theoretical**: Limited by available address space (64-bit systems)
- **Practical**: Tested with files up to 10GB
- **Optimization**: Automatic strategy selection based on file size

## 🔒 Security Requirements

### Cryptographic Dependencies

- **Ed25519**: Via ring crate (BoringSSL/AWS-LC backend)
- **Hash Algorithms**:
  - SHA family via ring (standard implementations)
  - BLAKE3 via optimized blake3 crate
- **Random Numbers**: Cryptographically secure via rand crate

### Key Management

- **Public Keys**: Stored in YAML format (human-readable)
- **Private Keys**: Generated locally, not persisted by default
- **Nonces**: Cryptographically random, collision-resistant

## 📋 Installation Methods

### From Source (Recommended)

```bash
git clone <repository-url>
cd signhash
cargo build --release
```

### Direct Installation

```bash
cargo install --path .
```

### System Package Managers

Package manager support may be added in future versions.

## ⚠️ Known Limitations

### File System

- **Case Sensitivity**: Behavior depends on underlying file system
- **Unicode**: Full Unicode path support, may vary by platform
- **Symlinks**: Detection supported, but target verification optional

### Performance

- **Small Files**: Memory mapping overhead for files <16KB
- **Network Storage**: Performance may degrade on network file systems
- **Concurrent Access**: No file locking, avoid concurrent modifications

### Platform-Specific

- **Windows**: Path length limitations in older versions
- **macOS**: Extended attributes not included in verification
- **Linux**: SELinux/AppArmor may affect file access patterns

## 🧪 Testing Requirements

### Test Execution

- **Unit Tests**: 289 comprehensive tests across 11 test files
- **Integration Tests**: End-to-end workflow validation
- **Benchmark Tests**: Performance regression detection
- **Documentation Tests**: All code examples verified

### Test Environment

- **Temporary Files**: Tests create and clean up temporary files
- **Parallel Execution**: Tests support parallel execution
- **Platform Testing**: Cross-platform compatibility validated

For more information about development workflows, see [`DEVELOPMENT.md`](DEVELOPMENT.md).
