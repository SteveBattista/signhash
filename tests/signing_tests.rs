//! Tests for signing and verification functions

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::rand::SystemRandom;

mod test_utils;

// Helper function to sign data (mimics sign_data)
fn sign_data(data: &str, private_key_bytes: &[u8]) -> ring::signature::Signature {
    let key_pair = Ed25519KeyPair::from_pkcs8(private_key_bytes)
        .unwrap_or_else(|why| panic!("Couldn't load key pair from PKCS8 data.|{}", why));
    key_pair.sign(data.as_bytes())
}

// Helper function to verify signature
fn verify_signature(public_key_bytes: &[u8], data: &str, signature: &[u8]) -> bool {
    let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
    public_key.verify(data.as_bytes(), signature).is_ok()
}

// ===== Signature Generation Tests =====

#[test]
fn test_sign_data_produces_signature() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    // Sign some data
    let data = "Test data to sign";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Verify signature exists and has correct length (64 bytes for Ed25519)
    assert_eq!(signature.as_ref().len(), 64);
}

#[test]
fn test_sign_data_deterministic() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    let data = "Same data to sign twice";
    
    // Sign the data twice with the same key
    let signature1 = sign_data(data, pkcs8_bytes.as_ref());
    let signature2 = sign_data(data, pkcs8_bytes.as_ref());
    
    // Ed25519 signatures are deterministic - same data + key = same signature
    assert_eq!(signature1.as_ref(), signature2.as_ref());
}

#[test]
fn test_sign_data_different_data() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    // Sign different data
    let data1 = "First message";
    let data2 = "Second message";
    
    let signature1 = sign_data(data1, pkcs8_bytes.as_ref());
    let signature2 = sign_data(data2, pkcs8_bytes.as_ref());
    
    // Different data should produce different signatures
    assert_ne!(signature1.as_ref(), signature2.as_ref());
}

#[test]
fn test_sign_data_different_keys() {
    // Generate two different key pairs
    let rng = SystemRandom::new();
    let pkcs8_bytes1 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pkcs8_bytes2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    let data = "Same data, different keys";
    
    // Sign with different keys
    let signature1 = sign_data(data, pkcs8_bytes1.as_ref());
    let signature2 = sign_data(data, pkcs8_bytes2.as_ref());
    
    // Different keys should produce different signatures
    assert_ne!(signature1.as_ref(), signature2.as_ref());
}

#[test]
fn test_signature_length() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    // Test various data lengths
    let long_string = "x".repeat(1000);
    let test_data = vec![
        "",
        "a",
        "Short message",
        "This is a longer message with more content",
        long_string.as_str(),
    ];
    
    for data in test_data {
        let signature = sign_data(data, pkcs8_bytes.as_ref());
        // Ed25519 signatures are always 64 bytes
        assert_eq!(signature.as_ref().len(), 64);
    }
}

#[test]
#[should_panic]
fn test_sign_data_invalid_key() {
    // Try to sign with invalid key data
    let invalid_key = [0u8; 50]; // Wrong length and format
    let data = "Test data";
    
    let _ = sign_data(data, &invalid_key); // Should panic
}

#[test]
#[should_panic]
fn test_sign_data_empty_key() {
    // Try to sign with empty key
    let empty_key = [];
    let data = "Test data";
    
    let _ = sign_data(data, &empty_key); // Should panic
}

// ===== Signature Verification Tests =====

#[test]
fn test_verify_signature_valid() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign data
    let data = "Data to verify";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Verify signature
    assert!(verify_signature(public_key, data, signature.as_ref()));
}

#[test]
fn test_verify_signature_invalid() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Create an invalid signature (random bytes)
    let invalid_signature = [0x42u8; 64];
    
    let data = "Data to verify";
    
    // Verification should fail
    assert!(!verify_signature(public_key, data, &invalid_signature));
}

#[test]
fn test_verify_signature_wrong_data() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign original data
    let original_data = "Original data";
    let signature = sign_data(original_data, pkcs8_bytes.as_ref());
    
    // Try to verify with modified data
    let modified_data = "Modified data";
    
    // Verification should fail
    assert!(!verify_signature(public_key, modified_data, signature.as_ref()));
}

#[test]
fn test_verify_signature_wrong_key() {
    // Generate two different key pairs
    let rng = SystemRandom::new();
    let pkcs8_bytes1 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pkcs8_bytes2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    let key_pair2 = Ed25519KeyPair::from_pkcs8(pkcs8_bytes2.as_ref()).unwrap();
    let wrong_public_key = key_pair2.public_key().as_ref();
    
    // Sign with first key
    let data = "Data signed with key 1";
    let signature = sign_data(data, pkcs8_bytes1.as_ref());
    
    // Try to verify with second key's public key
    // Verification should fail
    assert!(!verify_signature(wrong_public_key, data, signature.as_ref()));
}

#[test]
fn test_verify_signature_truncated() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign data
    let data = "Data to sign";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Try to verify with truncated signature
    let truncated_sig = &signature.as_ref()[..32]; // Only first 32 bytes
    
    // Verification should fail
    assert!(!verify_signature(public_key, data, truncated_sig));
}

// ===== Additional Edge Case Tests =====

#[test]
fn test_sign_empty_data() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign empty string
    let data = "";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Should still produce valid signature
    assert_eq!(signature.as_ref().len(), 64);
    
    // Should be verifiable
    assert!(verify_signature(public_key, data, signature.as_ref()));
}

#[test]
fn test_sign_large_data() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign large data (1MB)
    let large_data = "X".repeat(1_000_000);
    let signature = sign_data(&large_data, pkcs8_bytes.as_ref());
    
    // Signature should still be 64 bytes
    assert_eq!(signature.as_ref().len(), 64);
    
    // Should be verifiable
    assert!(verify_signature(public_key, &large_data, signature.as_ref()));
}

#[test]
fn test_sign_unicode_data() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign Unicode data
    let data = "Hello 世界 🌍 Привет مرحبا";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Should be verifiable
    assert!(verify_signature(public_key, data, signature.as_ref()));
}

#[test]
fn test_sign_special_characters() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign data with special characters
    let data = "Special|chars|with\nnewlines\tand\ttabs";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Should be verifiable
    assert!(verify_signature(public_key, data, signature.as_ref()));
}

#[test]
fn test_multiple_signatures_same_key() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign multiple different messages
    let messages = vec![
        "Message 1",
        "Message 2", 
        "Message 3",
        "Message 4",
        "Message 5",
    ];
    
    for msg in messages {
        let signature = sign_data(msg, pkcs8_bytes.as_ref());
        assert!(verify_signature(public_key, msg, signature.as_ref()));
    }
}

#[test]
fn test_signature_not_malleable() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign data
    let data = "Test malleability";
    let signature = sign_data(data, pkcs8_bytes.as_ref());
    
    // Try to modify signature slightly
    let mut modified_sig = signature.as_ref().to_vec();
    modified_sig[0] ^= 0x01; // Flip one bit
    
    // Modified signature should not verify
    assert!(!verify_signature(public_key, data, &modified_sig));
}

#[test]
fn test_verify_with_different_case() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    // Sign lowercase data
    let data_lower = "test data";
    let signature = sign_data(data_lower, pkcs8_bytes.as_ref());
    
    // Try to verify with uppercase data
    let data_upper = "TEST DATA";
    
    // Should fail - signatures are case-sensitive
    assert!(!verify_signature(public_key, data_upper, signature.as_ref()));
}

#[test]
fn test_signature_consistency() {
    // Generate a key pair
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref();
    
    let data = "Consistency test";
    
    // Sign multiple times
    let sig1 = sign_data(data, pkcs8_bytes.as_ref());
    let sig2 = sign_data(data, pkcs8_bytes.as_ref());
    let sig3 = sign_data(data, pkcs8_bytes.as_ref());
    
    // All signatures should be identical
    assert_eq!(sig1.as_ref(), sig2.as_ref());
    assert_eq!(sig2.as_ref(), sig3.as_ref());
    
    // All should verify
    assert!(verify_signature(public_key, data, sig1.as_ref()));
    assert!(verify_signature(public_key, data, sig2.as_ref()));
    assert!(verify_signature(public_key, data, sig3.as_ref()));
}

