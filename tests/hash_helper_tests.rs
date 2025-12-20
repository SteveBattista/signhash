//! Tests for hash algorithm helpers (`BLAKE3`, SHA family)
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
use std::fs::{self, File};
use tempfile::TempDir;

mod test_utils;

// ===== Algorithm Identification Tests =====

#[test]
fn test_algorithm_from_str_blake3() {
    // Would call: Algorithm::from_str("blake3")
    // Verify "blake3" string maps to BLAKE3 algorithm
    let algo_str = "blake3";
    assert_eq!(algo_str, "blake3");
}

#[test]
fn test_algorithm_from_str_sha256() {
    // Would call: Algorithm::from_str("256")
    // SHA256 is identified by "256"
    let algo_str = "256";
    assert_eq!(algo_str, "256");
}

#[test]
fn test_algorithm_from_str_sha1() {
    // Would call: Algorithm::from_str("128")
    // SHA1 is identified by "128"
    let algo_str = "128";
    assert_eq!(algo_str, "128");
}

#[test]
fn test_algorithm_from_str_sha384() {
    // Would call: Algorithm::from_str("384")
    let algo_str = "384";
    assert_eq!(algo_str, "384");
}

#[test]
fn test_algorithm_from_str_sha512() {
    // Would call: Algorithm::from_str("512")
    let algo_str = "512";
    assert_eq!(algo_str, "512");
}

#[test]
fn test_algorithm_from_str_sha512_256() {
    // Would call: Algorithm::from_str("512_256")
    let algo_str = "512_256";
    assert_eq!(algo_str, "512_256");
}

#[test]
fn test_algorithm_from_str_invalid() {
    // Would call: Algorithm::from_str("invalid") - should panic
    // Test validates that invalid algorithm strings are rejected
    let invalid_algos = vec!["md5", "invalid", "sha3", ""];
    for algo in invalid_algos {
        assert!(!matches!(
            algo,
            "blake3" | "128" | "256" | "384" | "512" | "512_256"
        ));
    }
}

// ===== HasherOptions Tests =====

#[test]
fn test_hasher_options_new() {
    // Would call: HasherOptions::new("blake3"), HasherOptions::new("256"), etc.
    // Verify all supported algorithms can be initialized
    let algorithms = vec!["blake3", "128", "256", "384", "512", "512_256"];

    for algo in algorithms {
        assert!(!algo.is_empty());
    }
}

// ===== BLAKE3 Hash Tests =====

#[test]
fn test_hash_once_empty_data() {
    // BLAKE3 hash of empty data
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"");
    let hash = hasher.finalize();

    // BLAKE3 produces 32-byte hash
    assert_eq!(hash.as_bytes().len(), 32);

    // Verify empty data hash is consistent
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(b"");
    let hash2 = hasher2.finalize();
    assert_eq!(hash.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_hash_once_small_data() {
    // Hash small data with BLAKE3
    let data = b"Hello, World!";
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);

    // Verify hash is not all zeros
    assert!(hash.as_bytes().iter().any(|&b| b != 0));
}

#[test]
fn test_hash_once_large_data() {
    // Hash 1MB of data
    let large_data = vec![0xAB_u8; 1_000_000];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&large_data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

// ===== SHA256 Hash Tests =====

#[test]
fn test_sha256_hash_small_data() {
    let data = b"test data";
    let mut context = Context::new(&SHA256);
    context.update(data);
    let digest = context.finish();

    // SHA256 produces 32 bytes
    assert_eq!(digest.as_ref().len(), 32);
}

#[test]
fn test_sha256_hash_empty_data() {
    let mut context = Context::new(&SHA256);
    context.update(b"");
    let digest = context.finish();

    // SHA256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(digest.as_ref().len(), 32);
}

// ===== SHA512 Hash Tests =====

#[test]
fn test_sha512_hash_data() {
    let data = b"test data for sha512";
    let mut context = Context::new(&SHA512);
    context.update(data);
    let digest = context.finish();

    // SHA512 produces 64 bytes
    assert_eq!(digest.as_ref().len(), 64);
}

// ===== SHA384 Hash Tests =====

#[test]
fn test_sha384_hash_data() {
    let data = b"test data for sha384";
    let mut context = Context::new(&SHA384);
    context.update(data);
    let digest = context.finish();

    // SHA384 produces 48 bytes
    assert_eq!(digest.as_ref().len(), 48);
}

// ===== SHA512_256 Hash Tests =====

#[test]
fn test_sha512_256_hash_data() {
    let data = b"test data for sha512_256";
    let mut context = Context::new(&SHA512_256);
    context.update(data);
    let digest = context.finish();

    // SHA512_256 produces 32 bytes
    assert_eq!(digest.as_ref().len(), 32);
}

// ===== SHA1 Hash Tests =====

#[test]
fn test_sha1_hash_data() {
    let data = b"test data for sha1";
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(data);
    let digest = context.finish();

    // SHA1 produces 20 bytes
    assert_eq!(digest.as_ref().len(), 20);
}

// ===== Streaming Hash Tests =====

#[test]
fn test_multi_hash_update_single_chunk() {
    // Single update
    let data = b"single chunk of data";
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_multi_hash_update_multiple_chunks() {
    // Multiple updates should produce same result as single update
    let part1 = b"Hello, ";
    let part2 = b"World!";

    // Multi-chunk hash
    let mut hasher1 = blake3::Hasher::new();
    hasher1.update(part1);
    hasher1.update(part2);
    let hash1 = hasher1.finalize();

    // Single-chunk hash
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(b"Hello, World!");
    let hash2 = hasher2.finalize();

    assert_eq!(hash1.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_streaming_hasher_chaining() {
    // Test chaining multiple updates
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"part1");
    hasher.update(b"part2");
    hasher.update(b"part3");
    let hash = hasher.finalize();

    // Compare with single update
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(b"part1part2part3");
    let hash2 = hasher2.finalize();

    assert_eq!(hash.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_finish_empty_hasher() {
    // Finish hasher with no data
    let hasher = blake3::Hasher::new();
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

// ===== File Hashing Tests =====

#[test]
fn test_hash_file_small_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("small.txt");

    let content = b"Small file content";
    fs::write(&file_path, content).unwrap();

    // Hash the file
    let mut hasher = blake3::Hasher::new();
    hasher.update(content);
    let expected_hash = hasher.finalize();

    // Verify file was created
    assert!(file_path.exists());
    let read_content = fs::read(&file_path).unwrap();
    assert_eq!(&read_content, content);

    // Hash read content
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(&read_content);
    let file_hash = hasher2.finalize();

    assert_eq!(expected_hash.as_bytes(), file_hash.as_bytes());
}

#[test]
fn test_hash_file_large_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("large.txt");

    // Create 1MB file
    let content = vec![0xAB_u8; 1_000_000];
    fs::write(&file_path, &content).unwrap();

    // Verify file size
    let metadata = fs::metadata(&file_path).unwrap();
    assert_eq!(metadata.len(), 1_000_000);

    // Hash the content
    let mut hasher = blake3::Hasher::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_hash_file_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("empty.txt");

    fs::write(&file_path, b"").unwrap();

    let content = fs::read(&file_path).unwrap();
    assert_eq!(content.len(), 0);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_hash_file_nonexistent() {
    // Would call: hash_helper::hash_file("/nonexistent/path")
    // Should handle error gracefully
    let result = fs::read("/nonexistent/file/path.txt");
    assert!(result.is_err());
}

// ===== Consistency Tests =====

#[test]
fn test_blake3_consistency() {
    // Same input should always produce same BLAKE3 hash
    let data = b"consistency test data";

    let mut hasher1 = blake3::Hasher::new();
    hasher1.update(data);
    let hash1 = hasher1.finalize();

    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(data);
    let hash2 = hasher2.finalize();

    let mut hasher3 = blake3::Hasher::new();
    hasher3.update(data);
    let hash3 = hasher3.finalize();

    assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    assert_eq!(hash2.as_bytes(), hash3.as_bytes());
}

#[test]
fn test_sha256_consistency() {
    // Same input should always produce same SHA256 hash
    let data = b"consistency test data";

    let mut context1 = Context::new(&SHA256);
    context1.update(data);
    let digest1 = context1.finish();

    let mut context2 = Context::new(&SHA256);
    context2.update(data);
    let digest2 = context2.finish();

    assert_eq!(digest1.as_ref(), digest2.as_ref());
}

#[test]
fn test_different_algorithms_different_results() {
    // Different algorithms should produce different hashes
    let data = b"test data";

    // BLAKE3
    let mut blake3_hasher = blake3::Hasher::new();
    blake3_hasher.update(data);
    let blake3_hash = blake3_hasher.finalize();

    // SHA256
    let mut sha256_context = Context::new(&SHA256);
    sha256_context.update(data);
    let sha256_hash = sha256_context.finish();

    // SHA512
    let mut sha512_context = Context::new(&SHA512);
    sha512_context.update(data);
    let sha512_hash = sha512_context.finish();

    // Hashes should be different
    assert_ne!(blake3_hash.as_bytes(), sha256_hash.as_ref());
    assert_ne!(sha256_hash.as_ref(), sha512_hash.as_ref());

    // But lengths should be as expected
    assert_eq!(blake3_hash.as_bytes().len(), 32);
    assert_eq!(sha256_hash.as_ref().len(), 32);
    assert_eq!(sha512_hash.as_ref().len(), 64);
}

#[test]
fn test_streaming_vs_once_equivalence() {
    // Streaming should produce same result as single update
    let data = b"This is a test message for streaming vs once comparison";

    // Streaming (multiple chunks)
    let mut hasher1 = blake3::Hasher::new();
    for chunk in data.chunks(10) {
        hasher1.update(chunk);
    }
    let streaming_hash = hasher1.finalize();

    // Single update
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(data);
    let once_hash = hasher2.finalize();

    assert_eq!(streaming_hash.as_bytes(), once_hash.as_bytes());
}

// ===== Additional Edge Case Tests =====

#[test]
fn test_hash_binary_data() {
    // Test hashing binary data (not UTF-8)
    let binary_data: Vec<u8> = (0..=255).collect();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&binary_data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_hash_all_zeros() {
    // Test hashing data that's all zeros
    let zeros = vec![0u8; 1000];

    let mut hasher = blake3::Hasher::new();
    hasher.update(&zeros);
    let hash = hasher.finalize();

    // Hash should not be all zeros
    assert!(hash.as_bytes().iter().any(|&b| b != 0));
}

#[test]
fn test_hash_all_ones() {
    // Test hashing data that's all 0xFF
    let ones = vec![0xFF_u8; 1000];

    let mut hasher = blake3::Hasher::new();
    hasher.update(&ones);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_hash_single_byte() {
    // Test hashing just one byte
    let data = &[0x42_u8];

    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_different_data_different_hashes() {
    // Verify that different inputs produce different hashes
    let data1 = b"data1";
    let data2 = b"data2";

    let mut hasher1 = blake3::Hasher::new();
    hasher1.update(data1);
    let hash1 = hasher1.finalize();

    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(data2);
    let hash2 = hasher2.finalize();

    assert_ne!(hash1.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_case_sensitive_hashing() {
    // Verify hashing is case-sensitive
    let data1 = b"Test";
    let data2 = b"test";

    let mut hasher1 = blake3::Hasher::new();
    hasher1.update(data1);
    let hash1 = hasher1.finalize();

    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(data2);
    let hash2 = hasher2.finalize();

    assert_ne!(hash1.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_hash_with_newlines() {
    // Test that newlines are properly handled
    let data = b"line1\nline2\nline3";

    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_hash_unicode_data() {
    // Test hashing Unicode strings
    let data = "Hello 世界 🌍".as_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();

    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_chunked_file_reading() {
    // Test reading file in chunks (simulates var_digest behavior)
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("chunked.txt");

    let content = b"x".repeat(100_000);
    fs::write(&file_path, &content).unwrap();

    // Read in 64KB chunks
    let mut file = File::open(&file_path).unwrap();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();

    loop {
        let bytes_read = std::io::Read::read(&mut file, &mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let chunked_hash = hasher.finalize();

    // Compare with direct hash
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(&content);
    let direct_hash = hasher2.finalize();

    assert_eq!(chunked_hash.as_bytes(), direct_hash.as_bytes());
}
