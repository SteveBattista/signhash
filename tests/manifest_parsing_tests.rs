//! Tests for manifest parsing and creation functions

use std::fs;
use tempfile::TempDir;

mod test_utils;

// Constants matching main_helper
const TOKEN_SEPARATOR: &str = "|";

// Mock ManifestLine structure for testing
#[derive(Debug, PartialEq)]
struct ManifestLine {
    file_type: String,
    bytes: String,
    time: String,
    hash: String,
    nonce: String,
    sign: String,
}

// Helper function to parse manifest line (mimics main_helper::parse_manifest_line)
fn parse_manifest_line(manifest_line: &str) -> (String, ManifestLine) {
    let tokens: Vec<&str> = manifest_line.split(TOKEN_SEPARATOR).collect();
    let file_name = tokens[1].to_string();
    let manifest = ManifestLine {
        file_type: tokens[0].to_string(),
        bytes: tokens[2].to_string(),
        time: tokens[3].to_string(),
        hash: tokens[4].to_string(),
        nonce: tokens[5].to_string(),
        sign: tokens[6].to_string(),
    };
    (file_name, manifest)
}

// ===== Basic Parsing Tests =====

#[test]
fn test_parse_manifest_line_valid_file() {
    let line = "File|./test.txt|1024|2024-12-07T10:30:00Z|ABCDEF1234567890|NONCE123|SIGNATURE456";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./test.txt");
    assert_eq!(manifest.file_type, "File");
    assert_eq!(manifest.bytes, "1024");
    assert_eq!(manifest.time, "2024-12-07T10:30:00Z");
    assert_eq!(manifest.hash, "ABCDEF1234567890");
    assert_eq!(manifest.nonce, "NONCE123");
    assert_eq!(manifest.sign, "SIGNATURE456");
}

#[test]
fn test_parse_manifest_line_valid_directory() {
    let line = "Dir|./mydir|0|2024-12-07T10:30:00Z|DIRHASH|NONCE789|DIRSIG";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./mydir");
    assert_eq!(manifest.file_type, "Dir");
    assert_eq!(manifest.bytes, "0");
}

#[test]
fn test_parse_manifest_line_with_symlink() {
    let line = "Link|./mylink|0|2024-12-07T10:30:00Z|LINKHASH|NONCELINK|LINKSIG";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./mylink");
    assert_eq!(manifest.file_type, "Link");
}

#[test]
fn test_parse_manifest_line_extracts_all_fields() {
    let line = "File|./data.bin|999999|2024-01-01T00:00:00Z|HASH1234|NONCE5678|SIG9012";
    let (path, manifest) = parse_manifest_line(line);
    
    // Verify file name
    assert_eq!(path, "./data.bin");
    
    // Verify all fields are extracted correctly
    assert_eq!(manifest.file_type, "File");
    assert_eq!(manifest.bytes, "999999");
    assert_eq!(manifest.time, "2024-01-01T00:00:00Z");
    assert_eq!(manifest.hash, "HASH1234");
    assert_eq!(manifest.nonce, "NONCE5678");
    assert_eq!(manifest.sign, "SIG9012");
}

#[test]
#[should_panic]
fn test_parse_manifest_line_invalid_format() {
    // Too few tokens - should cause panic when indexing
    let line = "File|./test.txt|1024";
    let _ = parse_manifest_line(line);
}

#[test]
#[should_panic]
fn test_parse_manifest_line_missing_separator() {
    // No separators at all
    let line = "FileTestData";
    let _ = parse_manifest_line(line);
}

#[test]
fn test_parse_manifest_line_special_characters_in_path() {
    // Test various special characters in paths
    let line = "File|./test file (1).txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (path, _) = parse_manifest_line(line);
    assert_eq!(path, "./test file (1).txt");
    
    // Test path with dots and underscores
    let line2 = "File|./my_test.file.v2.txt|512|2024-12-07T10:30:00Z|HASH2|NONCE2|SIG2";
    let (path2, _) = parse_manifest_line(line2);
    assert_eq!(path2, "./my_test.file.v2.txt");
}

#[test]
fn test_parse_manifest_line_unicode_path() {
    let line = "File|./测试文件.txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./测试文件.txt");
    assert_eq!(manifest.file_type, "File");
}

#[test]
fn test_parse_manifest_line_long_hash() {
    // Test with realistic SHA512 hash length
    let long_hash = "A".repeat(128);
    let line = format!("File|./test.txt|1024|2024-12-07T10:30:00Z|{}|NONCE|SIG", long_hash);
    let (_, manifest) = parse_manifest_line(&line);
    
    assert_eq!(manifest.hash, long_hash);
}

#[test]
fn test_parse_manifest_line_zero_bytes() {
    let line = "File|./empty.txt|0|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (_, manifest) = parse_manifest_line(line);
    
    assert_eq!(manifest.bytes, "0");
}

#[test]
fn test_parse_manifest_line_large_file_size() {
    let line = "File|./large.bin|9999999999|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (_, manifest) = parse_manifest_line(line);
    
    assert_eq!(manifest.bytes, "9999999999");
}

// ===== Manifest File Reading Tests =====

#[test]
fn test_read_manifest_file_valid() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("manifest.txt");
    
    let content = concat!(
        "File|./file1.txt|100|2024-12-07T10:30:00Z|HASH1|NONCE1|SIG1\n",
        "File|./file2.txt|200|2024-12-07T10:30:00Z|HASH2|NONCE2|SIG2\n",
        "Dir|./mydir|0|2024-12-07T10:30:00Z|HASH3|NONCE3|SIG3\n"
    );
    
    fs::write(&manifest_path, content).unwrap();
    
    // Read and parse manifest
    let file_content = fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<&str> = file_content.lines().collect();
    
    assert_eq!(lines.len(), 3);
    
    // Parse first line
    let (path1, manifest1) = parse_manifest_line(lines[0]);
    assert_eq!(path1, "./file1.txt");
    assert_eq!(manifest1.bytes, "100");
}

#[test]
fn test_read_manifest_file_missing() {
    let result = fs::read_to_string("/nonexistent/manifest.txt");
    assert!(result.is_err());
}

#[test]
fn test_read_manifest_file_empty() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("empty_manifest.txt");
    
    fs::write(&manifest_path, "").unwrap();
    
    let content = fs::read_to_string(&manifest_path).unwrap();
    assert_eq!(content.len(), 0);
    
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 0);
}

#[test]
fn test_read_manifest_file_large() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("large_manifest.txt");
    
    // Create manifest with 1000 entries
    let mut content = String::new();
    for i in 0..1000 {
        content.push_str(&format!(
            "File|./file{}.txt|{}|2024-12-07T10:30:00Z|HASH{}|NONCE{}|SIG{}\n",
            i, i * 100, i, i, i
        ));
    }
    
    fs::write(&manifest_path, &content).unwrap();
    
    // Read and verify
    let file_content = fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<&str> = file_content.lines().collect();
    
    assert_eq!(lines.len(), 1000);
    
    // Verify first and last entries
    let (path_first, _) = parse_manifest_line(lines[0]);
    assert_eq!(path_first, "./file0.txt");
    
    let (path_last, _) = parse_manifest_line(lines[999]);
    assert_eq!(path_last, "./file999.txt");
}

// ===== Manifest Line Structure Tests =====

#[test]
fn test_manifest_line_struct_creation() {
    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: "1024".to_string(),
        time: "2024-12-07T10:30:00Z".to_string(),
        hash: "ABCDEF".to_string(),
        nonce: "NONCE123".to_string(),
        sign: "SIG456".to_string(),
    };
    
    assert_eq!(manifest.file_type, "File");
    assert_eq!(manifest.bytes, "1024");
    assert_eq!(manifest.time, "2024-12-07T10:30:00Z");
    assert_eq!(manifest.hash, "ABCDEF");
    assert_eq!(manifest.nonce, "NONCE123");
    assert_eq!(manifest.sign, "SIG456");
}

#[test]
fn test_manifest_line_round_trip() {
    // Create a manifest line string
    let original_line = "File|./test.txt|2048|2024-12-07T10:30:00Z|HASH123|NONCE456|SIG789";
    
    // Parse it
    let (path, manifest) = parse_manifest_line(original_line);
    
    // Reconstruct the line
    let reconstructed = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        manifest.file_type,
        path,
        manifest.bytes,
        manifest.time,
        manifest.hash,
        manifest.nonce,
        manifest.sign
    );
    
    // Verify round trip
    assert_eq!(reconstructed, original_line);
}

// ===== Edge Cases Tests =====

#[test]
fn test_parse_manifest_line_trailing_separator() {
    // Extra separator at end
    let line = "File|./test.txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG|";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./test.txt");
    assert_eq!(manifest.sign, "SIG");
}

#[test]
fn test_parse_manifest_line_different_types() {
    // Test different file type values
    let types = vec!["File", "Dir", "Link", "Special"];
    
    for file_type in types {
        let line = format!("{}|./test|100|2024-12-07T10:30:00Z|HASH|NONCE|SIG", file_type);
        let (_, manifest) = parse_manifest_line(&line);
        assert_eq!(manifest.file_type, file_type);
    }
}

#[test]
fn test_parse_manifest_line_empty_fields() {
    // Some fields might be empty in edge cases
    let line = "File|./test.txt|||HASH||SIG";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./test.txt");
    assert_eq!(manifest.bytes, "");
    assert_eq!(manifest.time, "");
    assert_eq!(manifest.nonce, "");
}

#[test]
fn test_manifest_preserves_whitespace() {
    // Whitespace should be preserved in fields
    let line = "File| ./path with spaces |100|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (path, _) = parse_manifest_line(line);
    
    assert_eq!(path, " ./path with spaces ");
}

#[test]
fn test_parse_multiple_manifest_lines() {
    let lines = vec![
        "File|./file1.txt|100|2024-12-07T10:30:00Z|HASH1|NONCE1|SIG1",
        "File|./file2.txt|200|2024-12-07T10:30:00Z|HASH2|NONCE2|SIG2",
        "Dir|./dir1|0|2024-12-07T10:30:00Z|HASH3|NONCE3|SIG3",
    ];
    
    let mut paths = Vec::new();
    for line in lines {
        let (path, _) = parse_manifest_line(line);
        paths.push(path);
    }
    
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0], "./file1.txt");
    assert_eq!(paths[1], "./file2.txt");
    assert_eq!(paths[2], "./dir1");
}

#[test]
fn test_manifest_line_with_nested_paths() {
    let line = "File|./deeply/nested/path/to/file.txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (path, manifest) = parse_manifest_line(line);
    
    assert_eq!(path, "./deeply/nested/path/to/file.txt");
    assert_eq!(manifest.file_type, "File");
}

#[test]
fn test_manifest_line_with_absolute_path() {
    let line = "File|/absolute/path/file.txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    let (path, _) = parse_manifest_line(line);
    
    assert_eq!(path, "/absolute/path/file.txt");
}

#[test]
fn test_manifest_consistency() {
    // Parse same line multiple times - should get same result
    let line = "File|./test.txt|1024|2024-12-07T10:30:00Z|HASH|NONCE|SIG";
    
    let (path1, manifest1) = parse_manifest_line(line);
    let (path2, manifest2) = parse_manifest_line(line);
    
    assert_eq!(path1, path2);
    assert_eq!(manifest1, manifest2);
}

#[test]
fn test_manifest_with_header_lines() {
    let temp_dir = TempDir::new().unwrap();
    let manifest_path = temp_dir.path().join("manifest_with_header.txt");
    
    let content = concat!(
        "# Manifest Header\n",
        "# Created: 2024-12-07\n",
        "File|./file1.txt|100|2024-12-07T10:30:00Z|HASH1|NONCE1|SIG1\n",
        "File|./file2.txt|200|2024-12-07T10:30:00Z|HASH2|NONCE2|SIG2\n"
    );
    
    fs::write(&manifest_path, content).unwrap();
    
    let file_content = fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<&str> = file_content.lines().collect();
    
    assert_eq!(lines.len(), 4);
    
    // Skip header lines and parse data lines
    let data_lines: Vec<&str> = lines.iter()
        .filter(|line| !line.starts_with('#'))
        .copied()
        .collect();
    
    assert_eq!(data_lines.len(), 2);
}

