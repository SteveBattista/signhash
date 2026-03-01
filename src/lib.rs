//! SignHash Library
//!
//! A comprehensive cryptographic file hashing and signing library for creating
//! tamper-evident manifests and verifying file integrity.
//!
//! # Overview
//!
//! SignHash provides tools for:
//! - Creating cryptographically signed manifests of directory contents
//! - Verifying file integrity against signed manifests  
//! - Detecting tampering in both files and manifest metadata
//! - Multi-threaded parallel processing for performance
//!
//! # Architecture
//!
//! The library is organized into two main modules:
//!
//! - [`hash_helper`]: Unified hashing interface supporting multiple algorithms
//! - [`main_helper`]: High-level operations for manifest creation and verification
//!
//! # Algorithms
//!
//! ## Hash Algorithms
//! - **BLAKE3**: Modern, fast, cryptographically secure (recommended)
//! - **SHA256**: Industry standard, widely compatible  
//! - **SHA384/SHA512**: Higher security for sensitive applications
//! - **SHA1**: Legacy support only (not recommended)
//!
//! ## Digital Signatures
//! - **Ed25519**: High-performance elliptic curve signatures
//! - Post-quantum resistance planned for v2.0
//!
//! # Security Features
//!
//! - **Nonce Generation**: Prevents rainbow table and precomputation attacks
//! - **Manifest Integrity**: Self-verifying manifests with embedded signatures  
//! - **Timestamp Validation**: Detects file modification timestamps
//! - **Size Verification**: Validates file sizes haven't changed
//!
//! # Performance Optimizations
//!
//! - **Memory Mapping**: Zero-copy hashing for large files (≥16KB)
//! - **Adaptive Buffering**: Dynamic buffer sizing based on file size
//! - **Parallel Processing**: Multi-threaded operations using rayon
//! - **Streaming**: Constant memory usage regardless of file size
//!
//! # Examples
//!
//! ## Basic File Hashing
//!
//! ```rust
//! use signhash::{HasherOptions, hash_file};
//! use std::ffi::OsStr;
//!
//! // Create hasher for BLAKE3
//! let hasher = HasherOptions::new("blake3");
//!
//! // Hash a single file
//! let digest = hash_file(&hasher, OsStr::new("example.txt"));
//! println!("Hash: {}", hex::encode(&digest));
//! ```
//!
//! ## Streaming Hash Updates
//!
//! ```rust
//! use signhash::HasherOptions;
//!
//! let hasher = HasherOptions::new("256");
//! let result = hasher.multi_hash_update(b"hello")
//!                    .multi_hash_update(b" world")
//!                    .finish();
//! ```
//!
//! # Feature Flags
//!
//! - `memmap2` (default): Enable memory-mapped file I/O for performance
//!
//! # Thread Safety
//!
//! All types are thread-safe and designed for parallel processing.
//! [`HasherOptions`] can be cloned cheaply for use across threads.

pub mod hash_helper;
pub mod main_helper;

// Re-export commonly used types for convenience  
pub use hash_helper::{HasherOptions, Algorithm, ParseAlgorithmError, hash_file};

// Re-export main_helper types and functions
pub use main_helper::*;