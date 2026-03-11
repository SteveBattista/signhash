//! Hash helper module providing a unified interface for multiple hash algorithms.
//!
//! Supports BLAKE3 and various SHA algorithms via ring.

use blake3::Hasher as Blake3Hasher;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

#[cfg(feature = "memmap2")]
use anyhow::Result;
#[cfg(feature = "memmap2")]
use std::convert::TryFrom;

/// Minimum buffer size for streaming file reads (64 KiB).
const MIN_BUFFER_SIZE: usize = 64 * 1024;

/// Default buffer size for streaming file reads (256 KiB).
const DEFAULT_BUFFER_SIZE: usize = 256 * 1024;

/// Maximum buffer size for streaming file reads (4 MiB).
/// Prevents excessive memory usage for very large files.
const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Minimum file size (in bytes) to use memory mapping.
/// For files smaller than this, streaming is more efficient due to mmap overhead.
const MMAP_THRESHOLD: u64 = 16 * 1024; // 16 KiB

/// Error type for algorithm parsing failures.
#[derive(Debug, Clone)]
pub struct ParseAlgorithmError(String);

impl std::fmt::Display for ParseAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown hash algorithm: {}", self.0)
    }
}

impl std::error::Error for ParseAlgorithmError {}

/// Supported hash algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Blake3,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha512_256,
}

impl FromStr for Algorithm {
    type Err = ParseAlgorithmError;

    /// Parse algorithm from string identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use signhash::Algorithm;
    /// use std::str::FromStr;
    ///
    /// let algo = Algorithm::from_str("blake3").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ParseAlgorithmError` if the hash type string is not recognized.
    fn from_str(hash_type: &str) -> Result<Self, Self::Err> {
        match hash_type {
            "blake3" => Ok(Self::Blake3),
            "128" => Ok(Self::Sha1),
            "256" => Ok(Self::Sha256),
            "384" => Ok(Self::Sha384),
            "512" => Ok(Self::Sha512),
            "512_256" => Ok(Self::Sha512_256),
            _ => Err(ParseAlgorithmError(hash_type.to_string())),
        }
    }
}

/// Internal hasher state - either BLAKE3 or ring SHA.
enum HasherInner {
    Blake3(Box<Blake3Hasher>),
    Sha(Box<Context>),
}

impl HasherInner {
    /// Update the hasher with a chunk of data.
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake3(h) => {
                h.update(data);
            }
            Self::Sha(c) => c.update(data),
        }
    }

    /// Finalize the hash and return the digest as a byte vector.
    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Blake3(h) => h.finalize().as_bytes().to_vec(),
            Self::Sha(c) => c.finish().as_ref().to_vec(),
        }
    }
}

/// A hasher that can be cloned and reused for multiple files with the same algorithm.
#[derive(Clone)]
pub struct HasherOptions {
    algorithm: Algorithm,
}

impl HasherOptions {
    /// Create a new hasher configuration for the given algorithm string.
    ///
    /// # Panics
    /// Panics if the hash type is not recognized.
    #[must_use]
    pub fn new(hash_type: &str) -> Self {
        Self {
            algorithm: hash_type
                .parse()
                .unwrap_or_else(|e| panic!("Invalid hash algorithm '{hash_type}': {e}")),
        }
    }

    /// Create a fresh hasher instance for this algorithm.
    ///
    /// Returns a new `HasherInner` configured for the algorithm specified
    /// during construction.
    fn create_hasher(&self) -> HasherInner {
        match self.algorithm {
            Algorithm::Blake3 => HasherInner::Blake3(Box::new(Blake3Hasher::new())),
            Algorithm::Sha1 => HasherInner::Sha(Box::new(Context::new(&SHA1_FOR_LEGACY_USE_ONLY))),
            Algorithm::Sha256 => HasherInner::Sha(Box::new(Context::new(&SHA256))),
            Algorithm::Sha384 => HasherInner::Sha(Box::new(Context::new(&SHA384))),
            Algorithm::Sha512 => HasherInner::Sha(Box::new(Context::new(&SHA512))),
            Algorithm::Sha512_256 => HasherInner::Sha(Box::new(Context::new(&SHA512_256))),
        }
    }

    /// Hash a single chunk of data and return the digest.
    ///
    /// This is useful for one-shot hashing where you have all the data
    /// available at once. For streaming or incremental hashing, use
    /// `multi_hash_update` instead.
    #[must_use]
    pub fn hash_once(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.create_hasher();
        hasher.update(data);
        hasher.finalize()
    }

    /// Update hasher state with data and return a streaming hasher.
    ///
    /// This begins incremental hashing by consuming the `HasherOptions`
    /// and returning a `StreamingHasher` that can be used to continue
    /// adding data via chained calls.
    ///
    /// # Example
    /// ```ignore
    /// let hasher = HasherOptions::new("256");
    /// let result = hasher.multi_hash_update(b"hello")
    ///                    .multi_hash_update(b" world")
    ///                    .finish();
    /// ```
    #[must_use]
    pub fn multi_hash_update(self, input: &[u8]) -> StreamingHasher {
        let mut hasher = self.create_hasher();
        hasher.update(input);
        StreamingHasher { inner: hasher }
    }

    /// Finish a hasher that hasn't been fed any data.
    ///
    /// Returns the hash of an empty input for this algorithm.
    /// This is primarily used for initialization in certain contexts.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.create_hasher().finalize()
    }
}

/// A hasher that's in the middle of processing data.
pub struct StreamingHasher {
    inner: HasherInner,
}

impl StreamingHasher {
    /// Continue updating with more data.
    ///
    /// Consumes `self` and returns it back, allowing for method chaining.
    /// This pattern ensures the hasher is used in a linear fashion without
    /// accidentally duplicating state.
    #[must_use]
    pub fn multi_hash_update(mut self, input: &[u8]) -> Self {
        self.inner.update(input);
        self
    }

    /// Finalize and return the digest.
    ///
    /// Consumes the hasher and produces the final hash value as a byte vector.
    /// After calling this, the hasher cannot be used again.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.inner.finalize()
    }
}

/// Attempt to create a memory mapping for a file.
///
/// This function tries to memory-map the given file for fast reading.
/// Returns `Ok(None)` if the file cannot be mapped (e.g., not a regular file,
/// empty, or too large for address space).
///
/// # Safety
/// The memory mapping is only valid while the file remains unchanged.
/// The explicit length parameter helps prevent TOCTOU (time-of-check-time-of-use)
/// races where the file size changes between checking and mapping.
#[cfg(feature = "memmap2")]
fn try_memmap_file(file: &File) -> Result<Option<memmap2::Mmap>> {
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    // Skip mmap for small files - streaming is more efficient
    if !metadata.is_file() || file_size < MMAP_THRESHOLD {
        return Ok(None);
    }

    // Check if file fits in address space
    let Ok(len) = usize::try_from(file_size) else {
        return Ok(None);
    };

    // SAFETY: We've verified the file exists and has the expected size.
    // Setting explicit length prevents TOCTOU races with file modifications.
    let map = unsafe { memmap2::MmapOptions::new().len(len).map(file)? };
    Ok(Some(map))
}

/// Try to hash a file using memory mapping (fast path).
///
/// Attempts to use memory-mapped I/O to hash the file efficiently.
/// Returns `Some(digest)` if successful, `None` if memory mapping
/// is unavailable or fails.
///
/// Memory mapping is typically faster for large files as it avoids
/// intermediate buffering and allows the OS to optimize page caching.
/// Only uses mmap for files larger than `MMAP_THRESHOLD`.
fn try_hash_memmap(hasher: &HasherOptions, file: &File) -> Option<Vec<u8>> {
    #[cfg(feature = "memmap2")]
    {
        if let Ok(Some(map)) = try_memmap_file(file) {
            return Some(hasher.hash_once(&map));
        }
    }
    let _ = (hasher, file); // Suppress unused warnings when memmap disabled
    None
}

/// Calculate optimal buffer size based on file size.
///
/// Uses adaptive sizing:
/// - Small files (<1MB): 64 KiB buffer
/// - Medium files (1MB-10MB): 256 KiB buffer  
/// - Large files (10MB-100MB): 1 MiB buffer
/// - Very large files (>100MB): 4 MiB buffer (capped at `MAX_BUFFER_SIZE`)
///
/// This balances memory usage with I/O performance.
const fn calculate_buffer_size(file_size: Option<u64>) -> usize {
    match file_size {
        Some(size) if size < 1024 * 1024 => MIN_BUFFER_SIZE, // <1MB: 64KB
        Some(size) if size < 10 * 1024 * 1024 => DEFAULT_BUFFER_SIZE, // 1-10MB: 256KB
        Some(size) if size < 100 * 1024 * 1024 => 1024 * 1024, // 10-100MB: 1MB
        Some(_) => MAX_BUFFER_SIZE,                          // >100MB: 4MB
        None => DEFAULT_BUFFER_SIZE,                         // Unknown: 256KB
    }
}

/// Hash a file using streaming reads with adaptive buffer sizing.
///
/// Reads the file in chunks and incrementally updates the hash.
/// Uses adaptive buffer sizing based on file size for optimal performance.
/// This is slower than memory mapping but works for all file types
/// and doesn't require the memmap feature.
///
/// # Panics
/// Panics if reading from the file fails.
fn hash_streaming_file(hasher: &HasherOptions, file: &mut File) -> Vec<u8> {
    // Get file size for adaptive buffer sizing
    let file_size = file.metadata().ok().map(|m| m.len());
    let buffer_size = calculate_buffer_size(file_size);

    let mut inner = hasher.create_hasher();
    let mut buffer = vec![0_u8; buffer_size];

    loop {
        let count = file
            .read(&mut buffer)
            .unwrap_or_else(|e| panic!("Failed to read file for hashing: {e}"));

        if count == 0 {
            break;
        }
        inner.update(&buffer[..count]);
    }

    inner.finalize()
}

/// Hash a generic reader using streaming reads (fallback path).
///
/// Uses default buffer size since we cannot determine reader size.
///
/// # Panics
/// Panics if reading from the reader fails.
#[allow(dead_code)]
fn hash_streaming(hasher: &HasherOptions, mut reader: impl Read) -> Vec<u8> {
    let mut inner = hasher.create_hasher();
    let mut buffer = vec![0_u8; DEFAULT_BUFFER_SIZE];

    loop {
        let count = reader
            .read(&mut buffer)
            .unwrap_or_else(|e| panic!("Failed to read file for hashing: {e}"));

        if count == 0 {
            break;
        }
        inner.update(&buffer[..count]);
    }

    inner.finalize()
}

/// Hash a file, using memory mapping if available, falling back to streaming.
///
/// Automatically selects the best strategy:
/// - Files ≥16KB: Attempts memory mapping for zero-copy hashing
/// - Files <16KB or mmap failure: Uses adaptive streaming with buffer sizing
///
/// # Panics
/// Panics if the file cannot be opened or read.
#[must_use]
pub fn hash_file(hasher: &HasherOptions, filepath: &std::ffi::OsStr) -> Vec<u8> {
    use std::path::Path;
    let path = Path::new(filepath);
    let mut file = File::open(filepath)
        .unwrap_or_else(|e| panic!("Cannot open file {}: {}", path.display(), e));

    // Try fast path (memory-mapped) first
    if let Some(digest) = try_hash_memmap(hasher, &file) {
        return digest;
    }

    // Fall back to streaming with adaptive buffer size
    hash_streaming_file(hasher, &mut file)
}
