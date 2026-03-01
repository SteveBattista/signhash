//! SignHash File Signing Binary
//!
//! Creates cryptographically signed manifest files for directories.
//! Generates Ed25519 key pairs, computes file hashes using configurable
//! algorithms (SHA family or BLAKE3), and produces tamper-evident manifests.
//!
//! # Features
//!
//! - Multi-threaded file hashing using rayon
//! - Ed25519 digital signatures for integrity verification  
//! - Multiple hash algorithms: SHA1, SHA256, SHA384, SHA512, SHA512_256, BLAKE3
//! - Memory-mapped I/O for large files (≥16KB)
//! - Adaptive buffer sizing for optimal performance
//! - Unique nonce generation to prevent precomputed attacks
//! - Progress tracking with visual indicators
//!
//! # Usage
//!
//! ```bash
//! sign_hash -d /path/to/directory -o manifest.txt -u public.key
//! ```

use signhash::hash_helper::HasherOptions;
use signhash::main_helper::{
    collect_files, create_keys, create_line, create_progress_bar, get_pool_size,
    provide_unique_nonce, write_headers, write_key, write_manifest_from_channel, WriterContext,
    BITS_IN_BYTES, DEFAULT_PUBIC_KEY_FILE_NAME, NONCE_LENGTH_IN_BYTES, NO_OUTPUTFILE,
    PRIVATEKEY_LENGTH_IN_BYTES, PUBIC_KEY_STRING_ED25519, PUBLICKEY_LENGTH_IN_BYTES, PWD,
    SIGN_HEADER_MESSAGE_COUNT,
};

use rayon::prelude::*;
use std::collections::HashMap;
use std::env;
use std::io::{stdout, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use chrono::{DateTime, Utc};
use clap::{Arg, Command};

/// Build the command-line interface definition for `sign_hash`.
///
/// Creates a CLI parser with all supported arguments for file hashing and signing.
/// Includes comprehensive help text with examples and usage notes.
///
/// # Returns
///
/// Configured `Command` object ready for argument parsing.
fn build_cli() -> Command {
    Command::new("sign_hash")
        .version("1.0.0")
        .author("Stephen Battista <stephen.battista@gmail.com>")
        .about("Implements a signed hash for files")
        .arg(Arg::new("hash")
            .short('a').long("hash")
            .value_name("128|256|384|512|512_256|blake3")
            .help("Hash algorithm: SHA1(128), SHA256(256), SHA384(384), SHA512(512), SHA512_256(512_256), blake3. Default: SHA256"))
        .arg(Arg::new("signing")
            .short('s').long("signing")
            .value_name("ED25519")
            .help("Signing algorithm. Default: ED25519"))
        .arg(Arg::new("public")
            .short('u').long("public")
            .value_name("FILE")
            .help("Public key file location. Default: Signpub.txt"))
        .arg(Arg::new("output")
            .short('o').long("output")
            .value_name("FILE")
            .help("Manifest output file. Default: STDIO"))
        .arg(Arg::new("pool")
            .short('p').long("pool")
            .value_name("#")
            .help("Thread pool size. Default: CPU cores"))
        .arg(Arg::new("include")
            .short('i').long("include")
            .value_name("FILE")
            .help("Header file to include"))
        .arg(Arg::new("directory")
            .short('d').long("directory")
            .value_name("DIRECTORY")
            .help("Directory to hash. Default: current directory"))
        .after_help("EXAMPLES:
    # Hash current directory with default settings (SHA256)
    sign_hash
    
    # Hash specific directory and save manifest to file
    sign_hash -d /data -o manifest.txt
    
    # Use BLAKE3 algorithm with 4 threads
    sign_hash -d /data -a blake3 -p 4 -o manifest.txt
    
    # Hash with custom public key filename
    sign_hash -d /data -u MyKey.pub -o manifest.txt
    
    # Include custom header file in manifest
    sign_hash -d /data -i header.txt -o manifest.txt
    
    # Use SHA512 algorithm and output to stdout
    sign_hash -d /data -a 512
    
    # Full example with all options
    sign_hash -d /home/user/documents -a blake3 -p 8 -o docs_manifest.txt -u docs_key.pub

NOTES:
    - Public key file is automatically created (default: Signpub.txt)
    - Private key is never written to disk for security
    - Progress bars are shown when outputting to a file
    - Supports SHA1(128), SHA256(256), SHA384(384), SHA512(512), SHA512_256(512_256), blake3
    - Thread pool size defaults to CPU core count if not specified or set to 0")
}

/// Perform pre-flight validation before starting heavy operations.
///
/// Validates all inputs before beginning expensive file collection and hashing.
/// This prevents wasted work if inputs are invalid.
///
/// # Arguments
///
/// * `input_directory` - Directory to hash (must exist and be readable)
/// * `manifest_file` - Path for output manifest file
/// * `public_key_file` - Path where public key will be written
/// * `header_file` - Optional header file to include ("|||" means none)
/// * `fileoutput` - Whether output is to a file (vs STDIO)
///
/// # Returns
///
/// `Ok(())` if all inputs are valid, `Err(String)` with error message otherwise.
///
/// # Errors
///
/// Returns error if:
/// - Directory doesn't exist or isn't readable
/// - Header file doesn't exist or isn't readable (when specified)
/// - Output directory doesn't exist or isn't writable (when fileoutput=true)
/// - Public key directory doesn't exist
fn validate_inputs(
    input_directory: &str,
    manifest_file: &str,
    public_key_file: &str,
    header_file: &str,
    fileoutput: bool,
) -> Result<(), String> {
    // Validate input directory
    let dir_path = std::path::Path::new(input_directory);
    if !dir_path.exists() {
        return Err(format!("Directory '{input_directory}' does not exist"));
    }
    if !dir_path.is_dir() {
        return Err(format!("'{input_directory}' is not a directory"));
    }

    // Check if directory is readable
    if let Err(e) = std::fs::read_dir(input_directory) {
        return Err(format!("Cannot read directory '{input_directory}': {e}"));
    }

    // Validate header file if specified
    if header_file != "|||" {
        let header_path = std::path::Path::new(header_file);
        if !header_path.exists() {
            return Err(format!("Header file '{header_file}' does not exist"));
        }
        if !header_path.is_file() {
            return Err(format!("'{header_file}' is not a file"));
        }
    }

    // Validate output file can be created (if specified)
    if fileoutput {
        let manifest_path = std::path::Path::new(manifest_file);

        // Check if parent directory exists and is writable
        if let Some(parent) = manifest_path.parent() {
            if !parent.exists() {
                return Err(format!(
                    "Output directory '{}' does not exist",
                    parent.display()
                ));
            }

            // Try to create a test file to check write permissions
            let test_file = parent.join(".signhash_write_test");
            if let Err(e) = std::fs::File::create(&test_file) {
                return Err(format!(
                    "Cannot write to output directory '{}': {e}",
                    parent.display()
                ));
            }
            let _ = std::fs::remove_file(test_file);
        }

        // Warn if manifest file already exists
        if manifest_path.exists() {
            eprintln!(
                "Warning: Manifest file '{manifest_file}' already exists and will be overwritten"
            );
        }
    }

    // Validate public key file can be created
    let pubkey_path = std::path::Path::new(public_key_file);
    if let Some(parent) = pubkey_path.parent() {
        if !parent.exists() {
            return Err(format!(
                "Public key directory '{}' does not exist",
                parent.display()
            ));
        }
    }

    // Warn if public key file already exists
    if pubkey_path.exists() {
        eprintln!(
            "Warning: Public key file '{public_key_file}' already exists and will be overwritten"
        );
    }

    Ok(())
}

/// Entry point for the `sign_hash` binary.
///
/// Collects all files in the specified directory, computes cryptographic hashes,
/// generates a unique nonce for each file, signs each entry with Ed25519, and
/// produces a signed manifest file.
///
/// # Process
///
/// 1. Parse command-line arguments
/// 2. Validate all inputs (directory, files, permissions)
/// 3. Collect all files recursively from input directory
/// 4. Generate Ed25519 key pair and write public key to file
/// 5. Hash files in parallel using Rayon thread pool
/// 6. Sign each manifest entry with private key
/// 7. Write manifest with headers, file entries, and signature
///
/// Entry point for file hashing and signing operations.
///
/// Parses command line arguments, validates inputs, collects files from the target
/// directory, generates Ed25519 keys, and creates a cryptographically signed manifest
/// with file hashes and metadata.
///
/// # Process Overview
///
/// 1. Parse and validate command line arguments
/// 2. Generate Ed25519 key pair and write public key to file
/// 3. Collect all files from input directory recursively
/// 4. Create manifest headers with metadata and configuration
/// 5. Hash all files in parallel using rayon thread pool
/// 6. Generate unique nonces for each file to prevent rainbow table attacks
/// 7. Sign each manifest entry with Ed25519 private key
/// 8. Write complete signed manifest to output file or STDIO
///
/// # Exit Codes
///
/// - 0: Success  
/// - 1: Validation error, unsupported algorithm, or thread panic
///
/// # Exit Codes
///
/// - 0: Success
/// - 1: Validation error, unsupported algorithm, or thread panic
#[allow(clippy::too_many_lines)]
fn main() {
    let now: DateTime<Utc> = Utc::now();
    let start = Instant::now();
    let args: Vec<String> = env::args().collect();
    let matches = build_cli().get_matches();

    // Parse arguments
    let inputhash = matches
        .get_one::<String>("hash")
        .map_or("256", String::as_str);
    let hasher_option = HasherOptions::new(inputhash);

    let signing = matches
        .get_one::<String>("signing")
        .map_or("ED25519", String::as_str);
    if signing != "ED25519" {
        eprintln!("Error: Unsupported signing algorithm '{signing}'");
        eprintln!("Only ED25519 is currently supported.");
        std::process::exit(1);
    }

    let manifest_file = matches
        .get_one::<String>("output")
        .cloned()
        .unwrap_or_else(|| NO_OUTPUTFILE.to_string());
    let fileoutput = manifest_file != NO_OUTPUTFILE;

    let public_key_file = matches
        .get_one::<String>("public")
        .map_or(DEFAULT_PUBIC_KEY_FILE_NAME, String::as_str);
    let header_file = matches
        .get_one::<String>("include")
        .map_or("|||", String::as_str);
    let input_directory = matches
        .get_one::<String>("directory")
        .map_or(PWD, String::as_str);

    let poolnumber = get_pool_size(
        matches
            .get_one::<String>("pool")
            .map_or("0", String::as_str),
    );

    // Pre-flight validation
    if let Err(e) = validate_inputs(
        input_directory,
        &manifest_file,
        public_key_file,
        header_file,
        fileoutput,
    ) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    // Collect files
    let inputfiles = collect_files(input_directory, fileoutput);
    let num_files = inputfiles.len();

    // Generate keys
    let mut private_key_bytes = [0u8; PRIVATEKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut public_key_bytes = [0u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];
    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    write_key(&public_key_bytes, public_key_file, PUBIC_KEY_STRING_ED25519);

    // Setup channels and configure rayon thread pool
    let (sign_tx, sign_rx) = mpsc::channel();
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(poolnumber)
        .build_global()
    {
        eprintln!("Warning: Failed to configure thread pool: {e}. Using default configuration.");
    }

    // Write manifest headers
    write_headers(
        &sign_tx,
        inputhash,
        &args.join(" "),
        header_file,
        &now,
        poolnumber,
    );

    // Setup progress bar and writer thread
    let progress_bar =
        create_progress_bar(num_files as u64, "Hashing files:", "yellow", fileoutput);
    let thread_hasher = hasher_option.clone();

    let writer_child = thread::spawn(move || {
        let ctx = WriterContext {
            manifest_file: &manifest_file,
            progress_bar: &progress_bar,
            file_output: fileoutput,
        };
        write_manifest_from_channel(
            num_files + SIGN_HEADER_MESSAGE_COUNT,
            thread_hasher,
            &private_key_bytes,
            &sign_rx,
            start,
            ctx,
        );
    });

    // Hash files in parallel
    let mut nonce_bytes = [0u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut nonces: HashMap<[u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES], i32> = HashMap::new();

    if let Err(e) = stdout().flush() {
        eprintln!("Warning: Failed to flush stdout: {e}");
    }

    // Generate unique nonces for all files first
    let file_nonce_pairs: Vec<(String, [u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES])> = inputfiles
        .into_iter()
        .map(|file| {
            provide_unique_nonce(&mut nonce_bytes, &mut nonces, rand::rng());
            (file, nonce_bytes)
        })
        .collect();

    // Process files in parallel
    file_nonce_pairs.par_iter().for_each(|(file, nonce)| {
        create_line(file, &hasher_option, nonce, &private_key_bytes, &sign_tx);
    });

    // Wait for writer thread to finish and handle any errors
    if let Err(e) = writer_child.join() {
        eprintln!("Error: Writer thread panicked: {e:?}");
        std::process::exit(1);
    }
}
