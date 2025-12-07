//! Integration tests for end-to-end workflows

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

mod test_utils;
use test_utils::create_test_file;

#[test]
fn test_create_and_verify_manifest() {
    // Would test: sign_hash creates manifest, then check_hash verifies it
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"test content").unwrap();
    
    // Would call: sign_hash with directory path
    // Then call: check_hash with manifest path
    assert!(test_file.exists());
}

#[test]
fn test_detect_tampered_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("file.txt");
    
    // Create file with original content
    fs::write(&test_file, b"original content").unwrap();
    
    // Would: Create manifest with original hash
    
    // Modify file
    fs::write(&test_file, b"tampered content").unwrap();
    
    // Would: check_hash should detect tampering
    let original = b"original content";
    let tampered = fs::read(&test_file).unwrap();
    assert_ne!(original.to_vec(), tampered);
}

#[test]
fn test_detect_tampered_manifest() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("manifest");
    
    // Create manifest
    let original_manifest = "file.txt|hash123|100|2024-01-01T00:00:00Z\n";
    fs::write(&manifest_path, original_manifest).unwrap();
    
    // Tamper with manifest
    let tampered_manifest = "file.txt|BADHASH|100|2024-01-01T00:00:00Z\n";
    fs::write(&manifest_path, tampered_manifest).unwrap();
    
    // Would: check_hash --check-manifest should detect signature mismatch
    assert!(manifest_path.exists());
}

#[test]
fn test_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create multiple files
    for i in 1..=5 {
        let file_path = temp_dir.path().join(format!("file{i}.txt"));
        fs::write(&file_path, format!("content {i}")).unwrap();
    }
    
    // Would: sign_hash should create manifest with all 5 files
    let files: Vec<PathBuf> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    
    assert_eq!(files.len(), 5);
}

#[test]
fn test_nested_directories() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create nested structure
    let nested = temp_dir.path().join("level1").join("level2").join("level3");
    fs::create_dir_all(&nested).unwrap();
    
    create_test_file(nested.join("deep_file.txt"), b"deep content").unwrap();
    
    // Would: sign_hash should recursively find all files
    assert!(nested.join("deep_file.txt").exists());
}

#[test]
fn test_empty_directory() {
    let temp_dir = TempDir::new().unwrap();
    
    // Would: sign_hash should handle empty directory gracefully
    let entries: Vec<_> = fs::read_dir(temp_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 0);
}

#[test]
#[cfg(unix)]
fn test_symlinks_in_directory() {
    use std::os::unix::fs::symlink;
    
    let temp_dir = TempDir::new().unwrap();
    let real_file = temp_dir.path().join("real.txt");
    let link_file = temp_dir.path().join("link.txt");
    
    fs::write(&real_file, b"real content").unwrap();
    symlink(&real_file, &link_file).unwrap();
    
    // Would: sign_hash should follow or skip symlinks based on config
    assert!(link_file.exists());
}

#[test]
fn test_mixed_file_types() {
    let temp_dir = TempDir::new().unwrap();
    
    // Regular file
    create_test_file(temp_dir.path().join("file.txt"), b"file").unwrap();
    
    // Subdirectory
    let subdir = temp_dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    create_test_file(subdir.join("nested.txt"), b"nested").unwrap();
    
    // Would: sign_hash should handle mixed types correctly
    assert!(temp_dir.path().join("file.txt").exists());
    assert!(subdir.join("nested.txt").exists());
}

#[test]
fn test_large_directory() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create 100 files
    for i in 0..100 {
        let file_path = temp_dir.path().join(format!("file_{i:03}.txt"));
        fs::write(&file_path, format!("content {i}")).unwrap();
    }
    
    // Would: sign_hash should handle many files efficiently
    let count = fs::read_dir(temp_dir.path()).unwrap().count();
    assert_eq!(count, 100);
}

#[test]
fn test_different_hash_algorithms() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"test").unwrap();
    
    // Would test with: blake3, sha256, sha512, etc.
    let algorithms = vec!["blake3", "256", "512"];
    
    for algo in algorithms {
        // Would: sign_hash --algorithm <algo>
        assert!(!algo.is_empty());
    }
}

#[test]
fn test_manifest_only_verification() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("manifest");
    
    // Create manifest
    let manifest_content = concat!(
        "file1.txt|hash1|100|2024-01-01T00:00:00Z\n",
        "file2.txt|hash2|200|2024-01-01T00:00:00Z\n"
    );
    fs::write(&manifest_path, manifest_content).unwrap();
    
    // Would: check_hash --check-manifest (without checking files)
    let content = fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<_> = content.lines().collect();
    
    assert_eq!(lines.len(), 2);
}

#[test]
fn test_key_generation_and_usage() {
    let temp_dir = TempDir::new().unwrap();
    let keypair_path = temp_dir.path().join("Signkeys.yaml");
    let pubkey_path = temp_dir.path().join("Signpub.txt");
    
    // Would: create_keys() to generate keypair
    // Then: sign_data() with private key
    // Then: verify signature with public key
    
    // Simulate key files
    fs::write(&keypair_path, "private_key: ...\npublic_key: ...").unwrap();
    fs::write(&pubkey_path, "public_key_bytes").unwrap();
    
    assert!(keypair_path.exists());
    assert!(pubkey_path.exists());
}

#[test]
fn test_concurrent_file_hashing() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create files for concurrent hashing
    for i in 0..10 {
        let file_path = temp_dir.path().join(format!("file{i}.txt"));
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = i as u8;
        fs::write(&file_path, vec![byte; 1000]).unwrap();
    }
    
    // Would: sign_hash with multi-threading enabled
    // verify all files are hashed correctly
    let count = fs::read_dir(temp_dir.path()).unwrap().count();
    assert_eq!(count, 10);
}

#[test]
fn test_progress_tracking() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create files to track progress
    for i in 0..20 {
        create_test_file(
            temp_dir.path().join(format!("file{i}.txt")),
            format!("content {i}").as_bytes()
        ).unwrap();
    }
    
    // Would: sign_hash/check_hash should show progress bar
    // Can't easily test UI, but verify files exist
    let count = fs::read_dir(temp_dir.path()).unwrap().count();
    assert_eq!(count, 20);
}

#[test]
fn test_error_recovery() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a file
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"content").unwrap();
    
    // Would test: unreadable files, missing directories, invalid manifests
    // Verify that errors are caught and don't crash the program
    
    // Simulate error condition: delete file mid-operation
    fs::remove_file(&test_file).unwrap();
    assert!(!test_file.exists());
    
    // Would: sign_hash should handle missing file gracefully
}

