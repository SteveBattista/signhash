//! Hash helper module providing a unified interface for multiple hash algorithms.
//!
//! Supports BLAKE3 and various SHA algorithms via ring.

use blake3::Hasher as Blake3Hasher;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
use std::fs::File;
use std::io::Read;

#[cfg(feature = "memmap")]
use anyhow::Result;
#[cfg(feature = "memmap")]
use std::convert::TryFrom;

/// Buffer size for streaming file reads (64 KiB).
/// This is a reasonable default that balances memory usage with read efficiency.
const READ_BUFFER_SIZE: usize = 64 * 1024;

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

impl Algorithm {
    /// Parse algorithm from string identifier.
    ///
    /// # Panics
    /// Panics if the hash type string is not recognized.
    #[must_use]
    pub fn from_str(hash_type: &str) -> Self {
        match hash_type {
            "blake3" => Self::Blake3,
            "128" => Self::Sha1,
            "256" => Self::Sha256,
            "384" => Self::Sha384,
            "512" => Self::Sha512,
            "512_256" => Self::Sha512_256,
            _ => panic!("Unknown hash algorithm: {}", hash_type),
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
            algorithm: Algorithm::from_str(hash_type),
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
#[cfg(feature = "memmap")]
fn try_memmap_file(file: &File) -> Result<Option<memmap::Mmap>> {
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    // Can't mmap non-files or empty files
    if !metadata.is_file() || file_size == 0 {
        return Ok(None);
    }

    // Check if file fits in address space
    let Ok(len) = usize::try_from(file_size) else {
        return Ok(None);
    };

    // SAFETY: We've verified the file exists and has the expected size.
    // Setting explicit length prevents TOCTOU races with file modifications.
    let map = unsafe { memmap::MmapOptions::new().len(len).map(file)? };
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
fn try_hash_memmap(hasher: &HasherOptions, file: &File) -> Option<Vec<u8>> {
    #[cfg(feature = "memmap")]
    {
        if let Ok(Some(map)) = try_memmap_file(file) {
            return Some(hasher.hash_once(&map));
        }
    }
    let _ = (hasher, file); // Suppress unused warnings when memmap disabled
    None
}

/// Hash a file using streaming reads (fallback path).
///
/// Reads the file in chunks and incrementally updates the hash.
/// This is slower than memory mapping but works for all file types
/// and doesn't require the memmap feature.
///
/// # Panics
/// Panics if reading from the file fails.
fn hash_streaming(hasher: &HasherOptions, mut reader: impl Read) -> Vec<u8> {
    let mut inner = hasher.create_hasher();
    let mut buffer = vec![0_u8; READ_BUFFER_SIZE];

    loop {
        let count = reader
            .read(&mut buffer)
            .unwrap_or_else(|e| panic!("Failed to read file for hashing: {}", e));

        if count == 0 {
            break;
        }
        inner.update(&buffer[..count]);
    }

    inner.finalize()
}

/// Hash a file, using memory mapping if available, falling back to streaming.
///
/// # Panics
/// Panics if the file cannot be opened or read.
#[must_use]
pub fn hash_file(hasher: &HasherOptions, filepath: &std::ffi::OsStr) -> Vec<u8> {
    use std::path::Path;
    let path = Path::new(filepath);
    let file = File::open(filepath)
        .unwrap_or_else(|e| panic!("Cannot open file {}: {}", path.display(), e));

    // Try fast path (memory-mapped) first
    if let Some(digest) = try_hash_memmap(hasher, &file) {
        return digest;
    }

    // Fall back to streaming
    hash_streaming(hasher, file)
}
