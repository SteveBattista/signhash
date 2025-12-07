//! Common test utilities and helpers

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;


/// Create a temporary test file with specified content
///
/// # Errors
///
/// Returns an error if file creation or writing fails
pub fn create_test_file<P: AsRef<Path>>(path: P, content: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content)?;
    Ok(())
}

/// Create a test directory structure
///
/// # Errors
///
/// Returns an error if directory or file creation fails
pub fn create_test_directory(base: &Path, structure: &[&str]) -> std::io::Result<()> {
    for item in structure {
        let path = base.join(item);
        if item.ends_with('/') {
            fs::create_dir_all(path)?;
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(path)?;
        }
    }
    Ok(())
}

/// Generate test data of specified size
#[must_use]
pub fn generate_test_data(size: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Compare two byte slices with detailed error message
///
/// # Panics
///
/// Panics if the slices differ in length or content
pub fn assert_bytes_equal(actual: &[u8], expected: &[u8], context: &str) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{context}: length mismatch - actual: {}, expected: {}",
        actual.len(),
        expected.len()
    );
    
    for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            a, e,
            "{context}: byte mismatch at position {i} - actual: {a:02x}, expected: {e:02x}"
        );
    }
}

/// Convert hex string to bytes
///
/// # Panics
///
/// Panics if the hex string is invalid
#[must_use]
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Convert bytes to hex string
#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut result, "{b:02x}").unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_data() {
        let data = generate_test_data(256);
        assert_eq!(data.len(), 256);
        assert_eq!(data[0], 0);
        assert_eq!(data[255], 255);
        
        // Verify pattern continues
        let data_512 = generate_test_data(512);
        assert_eq!(data_512[256], 0);
        assert_eq!(data_512[257], 1);
    }

    #[test]
    fn test_hex_conversion_roundtrip() {
        let bytes = vec![0x12, 0x34, 0xab, 0xcd];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "1234abcd");
        let recovered = hex_to_bytes(&hex);
        assert_eq!(recovered, bytes);
    }
    
    #[test]
    fn test_hex_to_bytes_various() {
        assert_eq!(hex_to_bytes("00"), vec![0x00]);
        assert_eq!(hex_to_bytes("ff"), vec![0xff]);
        assert_eq!(hex_to_bytes("0102030405"), vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }
    
    #[test]
    fn test_bytes_to_hex_various() {
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), 
                   "0123456789abcdef");
    }
    
    #[test]
    fn test_create_test_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = b"test content";
        
        create_test_file(&file_path, content).unwrap();
        
        let read_content = std::fs::read(&file_path).unwrap();
        assert_eq!(read_content, content);
    }
    
    #[test]
    fn test_create_test_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let structure = &[
            "dir1/",
            "dir1/file1.txt",
            "dir2/",
            "dir2/subdir/",
            "dir2/subdir/file2.txt",
            "root_file.txt",
        ];
        
        create_test_directory(temp_dir.path(), structure).unwrap();
        
        assert!(temp_dir.path().join("dir1").is_dir());
        assert!(temp_dir.path().join("dir1/file1.txt").is_file());
        assert!(temp_dir.path().join("dir2/subdir").is_dir());
        assert!(temp_dir.path().join("dir2/subdir/file2.txt").is_file());
        assert!(temp_dir.path().join("root_file.txt").is_file());
    }
    
    #[test]
    fn test_assert_bytes_equal_success() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert_bytes_equal(&a, &b, "should be equal");
    }
    
    #[test]
    #[should_panic(expected = "length mismatch")]
    fn test_assert_bytes_equal_different_length() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4];
        assert_bytes_equal(&a, &b, "test");
    }
    
    #[test]
    #[should_panic(expected = "byte mismatch")]
    fn test_assert_bytes_equal_different_content() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 9, 4];
        assert_bytes_equal(&a, &b, "test");
    }
}
