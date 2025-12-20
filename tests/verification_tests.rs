//! Tests for file verification functions (`check_line`)

use chrono::{DateTime, Utc};
use data_encoding::HEXUPPER;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

// Mock structures (would be imported from main_helper in real implementation)
const PRINT_MESSAGE: u8 = 0;
const TICK_MESSAGE: u8 = 1;
const NO_HASH: &str = "0";
const NO_TIME: &str = "00/00/0000 00:00:00";

#[derive(Clone)]
struct CheckMessage {
    check_type: u8,
    text: String,
    #[allow(dead_code)]
    verbose: bool,
}

struct ManifestLine {
    file_type: String,
    bytes: String,
    time: String,
    hash: String,
    nonce: String,
    sign: String,
}

#[derive(Clone, Copy)]
enum HasherOptions {
    Blake3,
    #[allow(dead_code)]
    Sha256,
}

// Helper functions that mimic main_helper functionality
fn hash_file(hasher: HasherOptions, path: &std::path::Path) -> Vec<u8> {
    let contents = fs::read(path).unwrap();
    match hasher {
        HasherOptions::Blake3 => blake3::hash(&contents).as_bytes().to_vec(),
        HasherOptions::Sha256 => {
            use ring::digest::{digest, SHA256};
            digest(&SHA256, &contents).as_ref().to_vec()
        }
    }
}

fn sign_data(data: &str, private_key_bytes: &[u8]) -> ring::signature::Signature {
    let key_pair = Ed25519KeyPair::from_pkcs8(private_key_bytes).unwrap();
    key_pair.sign(data.as_bytes())
}

fn send_check_message(
    check_type: u8,
    text: String,
    verbose: bool,
    check_tx: &mpsc::Sender<CheckMessage>,
) {
    check_tx
        .send(CheckMessage {
            check_type,
            text,
            verbose,
        })
        .unwrap();
}

fn send_pass_fail_check_message(
    condition: bool,
    pass_msg: String,
    fail_msg: String,
    check_tx: &mpsc::Sender<CheckMessage>,
) {
    if condition {
        send_check_message(PRINT_MESSAGE, pass_msg, true, check_tx);
    } else {
        send_check_message(PRINT_MESSAGE, fail_msg, false, check_tx);
    }
}

#[allow(clippy::too_many_lines)]
fn check_line(
    path: &str,
    hasher: HasherOptions,
    manifest_struct: &ManifestLine,
    public_key_bytes: &[u8],
    check_tx: &mpsc::Sender<CheckMessage>,
    manifest_only: bool,
) {
    let line_type: String;
    let data: String;
    let digest_str: String;

    if manifest_only {
        data = format!(
            "{}|{}|{}|{}|{}|{}",
            manifest_struct.file_type,
            path,
            manifest_struct.bytes,
            manifest_struct.time,
            manifest_struct.hash,
            manifest_struct.nonce
        );
    } else {
        match fs::metadata(path) {
            Err(_) => {
                data = format!(
                    "{}|{}|{}|{}|{}|{}",
                    "Bad-symlink", path, 0, NO_TIME, NO_HASH, manifest_struct.nonce
                );
            }
            Ok(metadata) => {
                let metadata2 = fs::symlink_metadata(path).unwrap();
                let postfix = if metadata2.file_type().is_symlink() {
                    "-symlink"
                } else {
                    ""
                };
                let filelen = format!("{}", metadata.len());
                send_pass_fail_check_message(
                    filelen == manifest_struct.bytes,
                    format!("Correct|{path}|File length check passed.\n"),
                    format!(
                        "Failure|{}|{}|{}|File len check failed.\n",
                        path, manifest_struct.bytes, filelen
                    ),
                    check_tx,
                );

                let datetime = metadata.modified().unwrap();
                let datetime: DateTime<Utc> = datetime.into();
                let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

                send_pass_fail_check_message(
                    datetime_string == manifest_struct.time,
                    format!("Correct|{path}|Date check passed.\n"),
                    format!(
                        "Failure|{}|{}|{}|File date check failed.\n",
                        path, manifest_struct.time, datetime_string
                    ),
                    check_tx,
                );

                if metadata.is_dir() {
                    line_type = format!("Dir{postfix}");
                    digest_str = NO_HASH.to_string();
                } else {
                    line_type = if metadata.is_file() {
                        format!("File{postfix}")
                    } else {
                        format!("Unknown{postfix}")
                    };
                    let digest = hash_file(hasher, std::path::Path::new(path));
                    digest_str = HEXUPPER.encode(&digest);
                }

                send_pass_fail_check_message(
                    line_type == manifest_struct.file_type,
                    format!("Correct|{path}|File type check passed.\n"),
                    format!(
                        "Failure|{}|File type check failed|{}|{}\n",
                        path, manifest_struct.file_type, line_type
                    ),
                    check_tx,
                );

                send_pass_fail_check_message(
                    digest_str == manifest_struct.hash,
                    format!("Correct|{path}|Hash check passed.\n"),
                    format!(
                        "Failure|{}|Hash check failed|{}|{}.\n",
                        path, manifest_struct.hash, digest_str
                    ),
                    check_tx,
                );

                data = format!(
                    "{}|{}|{}|{}|{}|{}",
                    manifest_struct.file_type,
                    path,
                    manifest_struct.bytes,
                    manifest_struct.time,
                    manifest_struct.hash,
                    manifest_struct.nonce
                );
            }
        }
    }

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);

    let local_key = match HEXUPPER.decode(manifest_struct.sign.as_bytes()) {
        Ok(local_key) => local_key,
        Err(why) => {
            send_check_message(
                PRINT_MESSAGE,
                format!("Failure|{path}|Couldn't decode hex signature|{why}\n"),
                false,
                check_tx,
            );
            vec![0; 64]
        }
    };

    let mut signature_key_bytes: [u8; 64] = [0; 64];
    signature_key_bytes[..].clone_from_slice(&local_key[..]);

    match public_key.verify(data.as_bytes(), &signature_key_bytes[..]) {
        Ok(()) => {
            send_check_message(
                PRINT_MESSAGE,
                format!("Correct|{path}|Signature check passed. Can trust manifest line.\n"),
                true,
                check_tx,
            );
        }
        Err(_) => {
            send_check_message(
                PRINT_MESSAGE,
                format!("Failure|{path}|Signature check failed. Can't trust manifest line.\n"),
                false,
                check_tx,
            );
        }
    }
    send_check_message(TICK_MESSAGE, "Tick".to_string(), false, check_tx);
}

#[test]
fn test_check_line_valid_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    // Get actual file metadata
    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    // Calculate hash
    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    // Generate keys and sign
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    // Collect all messages
    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have pass messages for size, date, type, hash, signature, plus tick
    assert!(messages.len() >= 6);
    let pass_count = messages
        .iter()
        .filter(|m| m.text.starts_with("Correct"))
        .count();
    assert_eq!(pass_count, 5); // size, date, type, hash, signature
}

#[test]
fn test_check_line_modified_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Original content").unwrap();

    // Get metadata and hash for original
    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    // Generate keys and sign
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    // Now modify the file
    thread::sleep(Duration::from_millis(10));
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Modified content - different!").unwrap();

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure messages for size, date, and hash
    let failure_count = messages
        .iter()
        .filter(|m| m.text.starts_with("Failure"))
        .count();
    assert!(failure_count >= 2); // At least size and hash should fail
}

#[test]
fn test_check_line_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("nonexistent.txt");

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Create manifest for missing file
    let data = format!(
        "Bad-symlink|{}|0|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        NO_TIME,
        NO_HASH
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: "100".to_string(),
        time: "01/01/2024 12:00:00".to_string(),
        hash: "ABC123".to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // File doesn't exist, so it will be treated as bad symlink and signature should pass
    let signature_pass = messages
        .iter()
        .any(|m| m.text.contains("Signature check passed"));
    assert!(signature_pass);
}

#[test]
fn test_check_line_wrong_size() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Use wrong size in manifest (actual is 12 bytes)
    let wrong_size = "999";
    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        wrong_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: wrong_size.to_string(),
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure for file length
    let size_failure = messages
        .iter()
        .any(|m| m.text.contains("File len check failed"));
    assert!(size_failure);
}

#[test]
fn test_check_line_wrong_hash() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Use wrong hash
    let wrong_hash = "DEADBEEF123456789ABCDEF";
    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        datetime_string,
        wrong_hash
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: wrong_hash.to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure for hash check
    let hash_failure = messages
        .iter()
        .any(|m| m.text.contains("Hash check failed"));
    assert!(hash_failure);
}

#[test]
fn test_check_line_wrong_timestamp() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Use wrong timestamp
    let wrong_time = "01/01/1970 00:00:00";
    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        wrong_time,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: wrong_time.to_string(),
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure for date check
    let date_failure = messages
        .iter()
        .any(|m| m.text.contains("File date check failed"));
    assert!(date_failure);
}

#[test]
fn test_check_line_wrong_type() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("test_dir");
    fs::create_dir(&dir_path).unwrap();

    let metadata = fs::metadata(&dir_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Create manifest claiming it's a file (but it's actually a directory)
    let data = format!(
        "File|{}|0|{}|{}|nonce123",
        dir_path.to_str().unwrap(),
        datetime_string,
        NO_HASH
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: "0".to_string(),
        time: datetime_string,
        hash: NO_HASH.to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        dir_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure for file type check
    let type_failure = messages
        .iter()
        .any(|m| m.text.contains("File type check failed"));
    assert!(type_failure);
}

#[test]
fn test_check_line_invalid_signature() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Create tampered signature (just wrong bytes)
    let fake_signature = "A".repeat(128); // 64 bytes in hex

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: fake_signature,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have failure for signature check
    let signature_failure = messages
        .iter()
        .any(|m| m.text.contains("Signature check failed"));
    assert!(signature_failure);
}

#[test]
fn test_check_line_manifest_only_mode() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");

    // Don't create the file - manifest_only mode doesn't check filesystem

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "File|{}|100|01/01/2024 12:00:00|ABC123|nonce123",
        file_path.to_str().unwrap()
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: "100".to_string(),
        time: "01/01/2024 12:00:00".to_string(),
        hash: "ABC123".to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        true, // manifest_only = true
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // In manifest_only mode, signature should be checked but no file checks
    let signature_pass = messages
        .iter()
        .any(|m| m.text.contains("Signature check passed"));
    assert!(signature_pass);

    // Should NOT have file-specific checks
    let has_file_checks = messages
        .iter()
        .any(|m| m.text.contains("File length check") || m.text.contains("Date check"));
    assert!(!has_file_checks);
}

#[test]
fn test_check_line_directory() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("test_dir");
    fs::create_dir(&dir_path).unwrap();

    let metadata = fs::metadata(&dir_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "Dir|{}|0|{}|{}|nonce123",
        dir_path.to_str().unwrap(),
        datetime_string,
        NO_HASH
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "Dir".to_string(),
        bytes: "0".to_string(),
        time: datetime_string,
        hash: NO_HASH.to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        dir_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Directory checks should pass
    let type_pass = messages
        .iter()
        .any(|m| m.text.contains("File type check passed"));
    assert!(type_pass);

    let hash_pass = messages
        .iter()
        .any(|m| m.text.contains("Hash check passed"));
    assert!(hash_pass); // Hash should be NO_HASH for directories
}

#[test]
fn test_check_line_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let target_path = temp_dir.path().join("target.txt");
    let mut target_file = File::create(&target_path).unwrap();
    target_file.write_all(b"Target content").unwrap();

    let symlink_path = temp_dir.path().join("link.txt");
    unix_fs::symlink(&target_path, &symlink_path).unwrap();

    let metadata = fs::metadata(&symlink_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &symlink_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "File-symlink|{}|{}|{}|{}|nonce123",
        symlink_path.to_str().unwrap(),
        file_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File-symlink".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        symlink_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Symlink checks should pass
    let type_pass = messages
        .iter()
        .any(|m| m.text.contains("File type check passed"));
    assert!(type_pass);
}

#[test]
fn test_check_line_bad_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let target_path = temp_dir.path().join("nonexistent_target.txt");
    let symlink_path = temp_dir.path().join("broken_link.txt");
    unix_fs::symlink(&target_path, &symlink_path).unwrap();

    // symlink exists but target doesn't - this is a bad symlink

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "Bad-symlink|{}|0|{}|{}|nonce123",
        symlink_path.to_str().unwrap(),
        NO_TIME,
        NO_HASH
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File-symlink".to_string(),
        bytes: "100".to_string(),
        time: "01/01/2024 12:00:00".to_string(),
        hash: "ABC123".to_string(),
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let hasher = HasherOptions::Blake3;
    let (tx, rx) = mpsc::channel();
    check_line(
        symlink_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Signature should pass because we signed with Bad-symlink data
    let signature_pass = messages
        .iter()
        .any(|m| m.text.contains("Signature check passed"));
    assert!(signature_pass);
}

#[test]
fn test_check_line_sends_all_messages() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Should have all check types: size, date, type, hash, signature, tick
    assert!(messages.iter().any(|m| m.text.contains("length check")));
    assert!(messages.iter().any(|m| m.text.contains("Date check")));
    assert!(messages.iter().any(|m| m.text.contains("type check")));
    assert!(messages.iter().any(|m| m.text.contains("Hash check")));
    assert!(messages.iter().any(|m| m.text.contains("Signature check")));
    assert!(messages.iter().any(|m| m.text == "Tick"));

    // Check message types
    let print_messages = messages
        .iter()
        .filter(|m| m.check_type == PRINT_MESSAGE)
        .count();
    let tick_messages = messages
        .iter()
        .filter(|m| m.check_type == TICK_MESSAGE)
        .count();

    assert!(print_messages >= 5);
    assert_eq!(tick_messages, 1);
}

#[test]
fn test_check_line_signature_verification() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file.txt");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Test content").unwrap();

    let metadata = fs::metadata(&file_path).unwrap();
    let datetime: DateTime<Utc> = metadata.modified().unwrap().into();
    let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));
    let file_size = format!("{}", metadata.len());

    let hasher = HasherOptions::Blake3;
    let hash = hash_file(hasher, &file_path);
    let hash_str = HEXUPPER.encode(&hash);

    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Sign with correct data
    let data = format!(
        "File|{}|{}|{}|{}|nonce123",
        file_path.to_str().unwrap(),
        file_size,
        datetime_string,
        hash_str
    );
    let signature = sign_data(&data, pkcs8_bytes.as_ref());
    let signature_str = HEXUPPER.encode(signature.as_ref());

    let manifest = ManifestLine {
        file_type: "File".to_string(),
        bytes: file_size,
        time: datetime_string,
        hash: hash_str,
        nonce: "nonce123".to_string(),
        sign: signature_str,
    };

    let (tx, rx) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest,
        key_pair.public_key().as_ref(),
        &tx,
        false,
    );

    drop(tx);
    let messages: Vec<CheckMessage> = rx.iter().collect();

    // Signature verification should pass with correct key
    let signature_pass = messages.iter().any(|m| {
        m.text
            .contains("Signature check passed. Can trust manifest line")
    });
    assert!(signature_pass);

    // Now test with wrong public key
    let pkcs8_bytes2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair2 = Ed25519KeyPair::from_pkcs8(pkcs8_bytes2.as_ref()).unwrap();

    let manifest2 = manifest.clone();
    let (tx2, rx2) = mpsc::channel();
    check_line(
        file_path.to_str().unwrap(),
        hasher,
        &manifest2,
        key_pair2.public_key().as_ref(), // Different key
        &tx2,
        false,
    );

    drop(tx2);
    let messages2: Vec<CheckMessage> = rx2.iter().collect();

    // Signature verification should fail with wrong key
    let signature_fail = messages2.iter().any(|m| {
        m.text
            .contains("Signature check failed. Can't trust manifest line")
    });
    assert!(signature_fail);
}

// Additional helper to make ManifestLine cloneable for the last test
impl Clone for ManifestLine {
    fn clone(&self) -> Self {
        ManifestLine {
            file_type: self.file_type.clone(),
            bytes: self.bytes.clone(),
            time: self.time.clone(),
            hash: self.hash.clone(),
            nonce: self.nonce.clone(),
            sign: self.sign.clone(),
        }
    }
}
