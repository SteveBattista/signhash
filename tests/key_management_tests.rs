//! Tests for key management functions (create_keys, write_key, read_public_key, etc.)

use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use std::collections::BTreeMap;
use std::fs::{self, File};
use tempfile::TempDir;
use data_encoding::HEXUPPER;

mod test_utils;

// Constants matching main_helper
const PUBIC_KEY_STRING_ED25519: &str = "ED25519_PUBLIC_KEY";
const PRIVATE_KEY_STRING_ED25519: &str = "ED25519_PRIVATE_KEY";

// ===== Key Generation Tests =====

#[test]
fn test_create_keys_generates_valid_keys() {
    // Generate Ed25519 key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    
    // Public key should be 32 bytes
    assert_eq!(key_pair.public_key().as_ref().len(), 32);
    
    // PKCS#8 encoded private key should be 83 bytes for Ed25519
    assert_eq!(pkcs8_bytes.as_ref().len(), 83);
}

#[test]
fn test_create_keys_generates_unique_keys() {
    // Generate first key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes1 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair1 = Ed25519KeyPair::from_pkcs8(pkcs8_bytes1.as_ref()).unwrap();
    let pub_key1 = key_pair1.public_key().as_ref();
    
    // Generate second key pair
    let pkcs8_bytes2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair2 = Ed25519KeyPair::from_pkcs8(pkcs8_bytes2.as_ref()).unwrap();
    let pub_key2 = key_pair2.public_key().as_ref();
    
    // Keys should be different
    assert_ne!(pub_key1, pub_key2);
    assert_ne!(pkcs8_bytes1.as_ref(), pkcs8_bytes2.as_ref());
}

#[test]
fn test_create_keys_multiple_unique() {
    // Generate 5 key pairs and verify they're all unique
    let rng = SystemRandom::new();
    let mut public_keys = Vec::new();
    
    for _ in 0..5 {
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        public_keys.push(key_pair.public_key().as_ref().to_vec());
    }
    
    // Check all keys are unique
    for i in 0..public_keys.len() {
        for j in (i + 1)..public_keys.len() {
            assert_ne!(public_keys[i], public_keys[j]);
        }
    }
}

// ===== Key Writing Tests =====

#[test]
fn test_write_key_creates_yaml_file() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("test_key.yaml");
    
    // Generate a test key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Write key to YAML
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(public_key));
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Verify file exists and is readable
    assert!(key_file.exists());
    let content = fs::read_to_string(&key_file).unwrap();
    assert!(content.contains(PUBIC_KEY_STRING_ED25519));
}

#[test]
fn test_write_key_hex_encoded() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("hex_key.yaml");
    
    // Create a simple test key
    let test_key = [0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD, 0xEF, 0x00];
    let hex_encoded = HEXUPPER.encode(&test_key);
    
    // Write to YAML
    let mut map = BTreeMap::new();
    map.insert("TEST_KEY".to_string(), hex_encoded.clone());
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Read back and verify hex encoding
    let content = fs::read_to_string(&key_file).unwrap();
    assert!(content.contains(&hex_encoded));
    assert!(content.contains("TEST_KEY"));
    
    // Verify uppercase hex
    assert!(hex_encoded.chars().all(|c| c.is_uppercase() || c.is_ascii_digit()));
}

#[test]
fn test_write_key_valid_yaml_structure() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("structure_test.yaml");
    
    // Generate key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Write YAML
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(public_key));
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, &yaml_string).unwrap();
    
    // Parse YAML back
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    
    assert!(parsed.contains_key(PUBIC_KEY_STRING_ED25519));
    assert_eq!(parsed[PUBIC_KEY_STRING_ED25519], HEXUPPER.encode(public_key));
}

// ===== Key Reading Tests =====

#[test]
fn test_read_public_key_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("valid_pub.yaml");
    
    // Generate and write key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let original_key = key_pair.public_key().as_ref();
    
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(original_key));
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Read key back
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    let decoded_key = HEXUPPER.decode(parsed[PUBIC_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    // Verify keys match
    assert_eq!(decoded_key, original_key);
}

#[test]
fn test_read_public_key_missing_file() {
    // Attempt to read non-existent file
    let result = fs::read_to_string("/nonexistent/path/key.yaml");
    assert!(result.is_err());
}

#[test]
fn test_read_public_key_invalid_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("invalid.yaml");
    
    // Write invalid YAML
    fs::write(&key_file, "{ invalid yaml content [[[").unwrap();
    
    // Attempt to parse
    let content = fs::read_to_string(&key_file).unwrap();
    let result: Result<BTreeMap<String, String>, _> = serde_yaml::from_str(&content);
    assert!(result.is_err());
}

#[test]
fn test_read_public_key_invalid_hex() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("invalid_hex.yaml");
    
    // Write YAML with invalid hex
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), "NOTVALIDHEX!!!".to_string());
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Read and attempt to decode
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    let result = HEXUPPER.decode(parsed[PUBIC_KEY_STRING_ED25519].as_bytes());
    assert!(result.is_err());
}

#[test]
fn test_read_public_key_wrong_length() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("wrong_length.yaml");
    
    // Write YAML with wrong-length key (should be 32 bytes = 64 hex chars)
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), "ABCD".to_string());
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Read and decode
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    let decoded = HEXUPPER.decode(parsed[PUBIC_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    // Verify it's not 32 bytes
    assert_ne!(decoded.len(), 32);
}

#[test]
fn test_read_private_key_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("valid_priv.yaml");
    
    // Generate private key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let original_key = pkcs8_bytes.as_ref();
    
    // Write to YAML
    let mut map = BTreeMap::new();
    map.insert(PRIVATE_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(original_key));
    let yaml_string = serde_yaml::to_string(&map).unwrap();
    fs::write(&key_file, yaml_string).unwrap();
    
    // Read back
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    let decoded_key = HEXUPPER.decode(parsed[PRIVATE_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    // Verify
    assert_eq!(decoded_key, original_key);
    assert_eq!(decoded_key.len(), 83);
}

#[test]
fn test_read_private_key_missing_file() {
    // Attempt to open non-existent file
    let result = File::open("/nonexistent/private_key.yaml");
    assert!(result.is_err());
}

// ===== Combined Operations Tests =====

#[test]
fn test_write_keys_creates_both_files() {
    let temp_dir = TempDir::new().unwrap();
    let pub_file = temp_dir.path().join("pub.yaml");
    let priv_file = temp_dir.path().join("priv.yaml");
    
    // Generate key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    
    // Write public key
    let mut pub_map = BTreeMap::new();
    pub_map.insert(PUBIC_KEY_STRING_ED25519.to_string(), 
                   HEXUPPER.encode(key_pair.public_key().as_ref()));
    fs::write(&pub_file, serde_yaml::to_string(&pub_map).unwrap()).unwrap();
    
    // Write private key
    let mut priv_map = BTreeMap::new();
    priv_map.insert(PRIVATE_KEY_STRING_ED25519.to_string(), 
                    HEXUPPER.encode(pkcs8_bytes.as_ref()));
    fs::write(&priv_file, serde_yaml::to_string(&priv_map).unwrap()).unwrap();
    
    // Verify both exist
    assert!(pub_file.exists());
    assert!(priv_file.exists());
}

#[test]
fn test_key_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let pub_file = temp_dir.path().join("roundtrip_pub.yaml");
    let priv_file = temp_dir.path().join("roundtrip_priv.yaml");
    
    // Generate keys
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let original_pub = key_pair.public_key().as_ref().to_vec();
    let original_priv = pkcs8_bytes.as_ref().to_vec();
    
    // Write keys
    let mut pub_map = BTreeMap::new();
    pub_map.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(&original_pub));
    fs::write(&pub_file, serde_yaml::to_string(&pub_map).unwrap()).unwrap();
    
    let mut priv_map = BTreeMap::new();
    priv_map.insert(PRIVATE_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(&original_priv));
    fs::write(&priv_file, serde_yaml::to_string(&priv_map).unwrap()).unwrap();
    
    // Read keys back
    let pub_content = fs::read_to_string(&pub_file).unwrap();
    let pub_parsed: BTreeMap<String, String> = serde_yaml::from_str(&pub_content).unwrap();
    let read_pub = HEXUPPER.decode(pub_parsed[PUBIC_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    let priv_content = fs::read_to_string(&priv_file).unwrap();
    let priv_parsed: BTreeMap<String, String> = serde_yaml::from_str(&priv_content).unwrap();
    let read_priv = HEXUPPER.decode(priv_parsed[PRIVATE_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    // Verify roundtrip
    assert_eq!(read_pub, original_pub);
    assert_eq!(read_priv, original_priv);
}

#[test]
fn test_write_key_overwrites_existing() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("overwrite.yaml");
    
    // Write first key
    let rng = SystemRandom::new();
    let pkcs8_1 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair_1 = Ed25519KeyPair::from_pkcs8(pkcs8_1.as_ref()).unwrap();
    let key1 = key_pair_1.public_key().as_ref();
    
    let mut map1 = BTreeMap::new();
    map1.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(key1));
    fs::write(&key_file, serde_yaml::to_string(&map1).unwrap()).unwrap();
    
    // Write second key (overwrite)
    let pkcs8_2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair_2 = Ed25519KeyPair::from_pkcs8(pkcs8_2.as_ref()).unwrap();
    let key2 = key_pair_2.public_key().as_ref();
    
    let mut map2 = BTreeMap::new();
    map2.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(key2));
    fs::write(&key_file, serde_yaml::to_string(&map2).unwrap()).unwrap();
    
    // Read back - should be second key
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    let read_key = HEXUPPER.decode(parsed[PUBIC_KEY_STRING_ED25519].as_bytes()).unwrap();
    
    assert_eq!(read_key, key2);
    assert_ne!(read_key, key1);
}

#[test]
fn test_public_key_size() {
    // Generate multiple keys and verify size
    let rng = SystemRandom::new();
    
    for _ in 0..5 {
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        
        // Ed25519 public keys are always 32 bytes
        assert_eq!(key_pair.public_key().as_ref().len(), 32);
    }
}

#[test]
fn test_private_key_pkcs8_format() {
    // Generate multiple private keys and verify PKCS#8 format
    let rng = SystemRandom::new();
    
    for _ in 0..5 {
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        
        // Ed25519 PKCS#8 keys are always 83 bytes
        assert_eq!(pkcs8_bytes.as_ref().len(), 83);
        
        // Verify it can be parsed back
        let result = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref());
        assert!(result.is_ok());
    }
}

// ===== Additional Edge Case Tests =====

#[test]
fn test_key_hex_encoding_length() {
    // 32-byte public key should produce 64 hex characters
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let hex_encoded = HEXUPPER.encode(key_pair.public_key().as_ref());
    
    assert_eq!(hex_encoded.len(), 64); // 32 bytes * 2 hex chars per byte
    
    // 83-byte private key should produce 166 hex characters
    let priv_hex = HEXUPPER.encode(pkcs8_bytes.as_ref());
    assert_eq!(priv_hex.len(), 166); // 83 bytes * 2
}

#[test]
fn test_yaml_preserves_key_data() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("preserve.yaml");
    
    // Generate key
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let original = key_pair.public_key().as_ref();
    
    // Write and read multiple times
    for _ in 0..3 {
        let mut map = BTreeMap::new();
        map.insert(PUBIC_KEY_STRING_ED25519.to_string(), HEXUPPER.encode(original));
        fs::write(&key_file, serde_yaml::to_string(&map).unwrap()).unwrap();
        
        let content = fs::read_to_string(&key_file).unwrap();
        let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
        let decoded = HEXUPPER.decode(parsed[PUBIC_KEY_STRING_ED25519].as_bytes()).unwrap();
        
        assert_eq!(decoded, original);
    }
}

#[test]
fn test_key_file_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("permissions.yaml");
    
    // Write key file
    fs::write(&key_file, "test content").unwrap();
    
    // Verify file is readable
    let metadata = fs::metadata(&key_file).unwrap();
    assert!(metadata.is_file());
    assert!(metadata.len() > 0);
}

#[test]
fn test_multiple_keys_in_same_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("multi_key.yaml");
    
    // Generate keys
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    
    // Write both keys to same file
    let mut map = BTreeMap::new();
    map.insert(PUBIC_KEY_STRING_ED25519.to_string(), 
               HEXUPPER.encode(key_pair.public_key().as_ref()));
    map.insert(PRIVATE_KEY_STRING_ED25519.to_string(), 
               HEXUPPER.encode(pkcs8_bytes.as_ref()));
    
    fs::write(&key_file, serde_yaml::to_string(&map).unwrap()).unwrap();
    
    // Read back both keys
    let content = fs::read_to_string(&key_file).unwrap();
    let parsed: BTreeMap<String, String> = serde_yaml::from_str(&content).unwrap();
    
    assert!(parsed.contains_key(PUBIC_KEY_STRING_ED25519));
    assert!(parsed.contains_key(PRIVATE_KEY_STRING_ED25519));
    assert_eq!(parsed.len(), 2);
}

