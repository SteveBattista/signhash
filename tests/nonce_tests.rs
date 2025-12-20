//! Tests for nonce generation and management

use data_encoding::HEXUPPER;
use rand::rngs::ThreadRng;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::channel;

mod test_utils;

// Constants matching main_helper
const NONCE_LENGTH_IN_BYTES: usize = 1024;
const BITS_IN_BYTES: usize = 8;
const PRINT_MESSAGE: u8 = 0;

// Mock structures
#[derive(Debug)]
struct CheckMessage {
    check_type: u8,
    text: String,
    verbose: bool,
}

// Helper function to generate a unique nonce (mimics provide_unique_nonce)
fn provide_unique_nonce<S: std::hash::BuildHasher>(
    nonce_bytes: &mut [u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES],
    nonces: &mut HashMap<[u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES], i32, S>,
    rng: &mut ThreadRng,
) {
    let mut duplicate = true;
    while duplicate {
        #[allow(clippy::cast_possible_truncation)]
        for item in nonce_bytes.iter_mut() {
            *item = rng.next_u32() as u8;
        }
        if nonces.contains_key(nonce_bytes) {
            eprintln!(
                "!!Duplicated nonce|{}|making a new one.",
                HEXUPPER.encode(nonce_bytes)
            );
        } else {
            duplicate = false;
            nonces.insert(*nonce_bytes, 0);
        }
    }
}

// Helper function to report and insert nonce (mimics report_duplicative_and_insert_nonce)
fn report_duplicative_and_insert_nonce<S: std::hash::BuildHasher>(
    nonces: &mut HashMap<String, String, S>,
    nonce: &str,
    file_name_line: &str,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    match nonces.insert(nonce.to_string(), file_name_line.to_string()) {
        None => (),
        Some(answer) => {
            let message = CheckMessage {
                check_type: PRINT_MESSAGE,
                text: format!("Failure|{nonce}|and|{answer}|share the same nonce.\n"),
                verbose: false,
            };
            check_tx.send(message).unwrap();
        }
    }
}

// ===== Nonce Generation Tests =====

#[test]
fn test_provide_unique_nonce_generates_nonce() {
    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Verify nonce was filled (not all zeros)
    assert!(nonce_bytes.iter().any(|&b| b != 0));
}

#[test]
#[allow(clippy::similar_names)]
fn test_provide_unique_nonce_unique() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate multiple nonces
    let mut nonce1 = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut nonce2 = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut nonce3 = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];

    provide_unique_nonce(&mut nonce1, &mut nonces, &mut rng);
    provide_unique_nonce(&mut nonce2, &mut nonces, &mut rng);
    provide_unique_nonce(&mut nonce3, &mut nonces, &mut rng);

    // Verify all nonces are different
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce1, nonce3);
}

#[test]
#[allow(clippy::similar_names)]
fn test_provide_unique_nonce_avoids_duplicates() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate and store first nonce
    let mut nonce1 = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce1, &mut nonces, &mut rng);

    // Generate second nonce - should be different
    let mut nonce2 = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce2, &mut nonces, &mut rng);

    // Verify nonce2 is not in the existing set before it was added
    assert_ne!(nonce1, nonce2);
    assert_eq!(nonces.len(), 2);
}

#[test]
fn test_provide_unique_nonce_inserts_into_map() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    assert_eq!(nonces.len(), 0);

    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Verify nonce was inserted
    assert_eq!(nonces.len(), 1);
    assert!(nonces.contains_key(&nonce_bytes));
}

#[test]
fn test_nonce_length_128_bytes() {
    // Verify nonce length constant
    const NONCE_BYTE_SIZE: usize = NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES;
    assert_eq!(NONCE_BYTE_SIZE, 128); // 1024 bits / 8 bits per byte = 128 bytes

    let nonce_array = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    assert_eq!(nonce_array.len(), 128);
}

#[test]
fn test_multiple_nonce_generation() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate 10 nonces
    for _ in 0..10 {
        let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
        provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);
    }

    // Verify all 10 are unique
    assert_eq!(nonces.len(), 10);
}

// ===== Duplicate Detection Tests =====

#[test]
fn test_report_duplicative_nonce_detects_duplicate() {
    let mut nonces = HashMap::new();
    let (tx, rx) = channel();

    // Insert first nonce
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE123", "file1.txt", &tx);

    // Try to insert duplicate
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE123", "file2.txt", &tx);

    // Should receive duplicate message
    let message = rx.try_recv();
    assert!(message.is_ok());

    let msg = message.unwrap();
    assert!(msg.text.contains("Failure"));
    assert!(msg.text.contains("NONCE123"));
}

#[test]
fn test_report_duplicative_nonce_inserts_new() {
    let mut nonces = HashMap::new();
    let (tx, rx) = channel();

    report_duplicative_and_insert_nonce(&mut nonces, "NONCE123", "file1.txt", &tx);

    // Verify nonce was inserted
    assert_eq!(nonces.len(), 1);
    assert!(nonces.contains_key("NONCE123"));

    // No message should be sent for new nonce
    let message = rx.try_recv();
    assert!(message.is_err());
}

#[test]
fn test_report_duplicative_nonce_sends_message() {
    let mut nonces = HashMap::new();
    let (tx, rx) = channel();

    // Insert first nonce with file1
    report_duplicative_and_insert_nonce(&mut nonces, "DUPLICATE", "file1.txt", &tx);

    // Insert duplicate with file2
    report_duplicative_and_insert_nonce(&mut nonces, "DUPLICATE", "file2.txt", &tx);

    // Receive and verify message
    let message = rx.recv().unwrap();
    assert_eq!(message.check_type, PRINT_MESSAGE);
    assert!(message.text.contains("DUPLICATE"));
    assert!(message.text.contains("file1.txt"));
    assert!(!message.verbose);
}

#[test]
fn test_report_multiple_unique_nonces() {
    let mut nonces = HashMap::new();
    let (tx, rx) = channel();

    // Insert multiple unique nonces
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE1", "file1.txt", &tx);
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE2", "file2.txt", &tx);
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE3", "file3.txt", &tx);

    // No messages should be sent
    assert!(rx.try_recv().is_err());
    assert_eq!(nonces.len(), 3);
}

// ===== Statistical Tests =====

#[test]
fn test_nonce_collision_probability() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate 100 nonces - should have no collisions
    for _ in 0..100 {
        let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
        provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);
    }

    // All 100 should be unique
    assert_eq!(nonces.len(), 100);
}

#[test]
fn test_nonce_randomness() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate nonces and check for basic randomness
    let mut all_bytes = Vec::new();

    for _ in 0..10 {
        let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
        provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);
        all_bytes.extend_from_slice(&nonce_bytes);
    }

    // Check that bytes are distributed (not all same value)
    let unique_values: HashSet<u8> = all_bytes.iter().copied().collect();

    // Should have many different byte values (good entropy)
    assert!(unique_values.len() > 200); // Out of 256 possible values
}

// ===== Encoding Tests =====

#[test]
fn test_nonce_hex_encoding() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Encode to hex
    let hex_encoded = HEXUPPER.encode(&nonce_bytes);

    // 128 bytes should produce 256 hex characters
    assert_eq!(hex_encoded.len(), 256);

    // Should be uppercase hex
    assert!(hex_encoded
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
}

#[test]
fn test_nonce_hex_roundtrip() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Encode and decode
    let hex_encoded = HEXUPPER.encode(&nonce_bytes);
    let decoded = HEXUPPER.decode(hex_encoded.as_bytes()).unwrap();

    // Should match original
    assert_eq!(decoded, nonce_bytes.to_vec());
}

// ===== Edge Cases =====

#[test]
fn test_nonce_map_capacity() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate many nonces to test map capacity
    for i in 0..1000 {
        let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
        provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);
        assert_eq!(nonces.len(), i + 1);
    }
}

#[test]
fn test_report_nonce_with_special_characters() {
    let mut nonces = HashMap::new();
    let (tx, _rx) = channel();

    // Test with special characters in file names
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE1", "file (1).txt", &tx);
    report_duplicative_and_insert_nonce(&mut nonces, "NONCE2", "file-2_test.txt", &tx);

    assert_eq!(nonces.len(), 2);
}

#[test]
fn test_nonce_consistency_check() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Verify the nonce stays in the map
    assert!(nonces.contains_key(&nonce_bytes));

    // Try to check it again
    assert!(nonces.contains_key(&nonce_bytes));
    assert_eq!(nonces.len(), 1);
}

#[test]
fn test_empty_nonce_map() {
    let nonces: HashMap<[u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES], i32> = HashMap::new();

    assert_eq!(nonces.len(), 0);
    assert!(nonces.is_empty());
}

#[test]
fn test_nonce_value_distribution() {
    let mut nonces = HashMap::new();
    let mut rng = rand::rng();

    // Generate a nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    provide_unique_nonce(&mut nonce_bytes, &mut nonces, &mut rng);

    // Count different byte values
    let mut byte_counts = [0u32; 256];
    for &byte in &nonce_bytes {
        byte_counts[byte as usize] += 1;
    }

    // Check that many different byte values are used
    let used_values = byte_counts.iter().filter(|&&count| count > 0).count();

    // With 128 random bytes, we expect good distribution
    assert!(used_values > 60); // At least 60 different byte values
}
