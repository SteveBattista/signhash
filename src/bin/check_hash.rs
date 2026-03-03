//! `SignHash` Verification Binary
//!
//! Verifies file integrity against cryptographically signed manifests.
//! Validates Ed25519 signatures, checks file hashes, and detects tampering
//! in both individual files and the manifest itself.
//!
//! # Features
//!
//! - Multi-threaded file verification using rayon
//! - Ed25519 signature verification against public keys
//! - Support for all `SignHash` algorithms: SHA1, SHA256, SHA384, SHA512, `SHA512_256`, BLAKE3
//! - Duplicate nonce detection for security validation
//! - Comprehensive tamper detection (size, timestamp, hash, signature)
//! - Progress tracking with detailed reporting
//! - Verbose and quiet output modes
//!
//! # Usage
//!
//! ```bash
//! check_hash -i manifest.txt -u public.key -d /path/to/directory
//! ```

use signhash::hash_helper::{self, HasherOptions};
use signhash::main_helper::{
    check_line, collect_files, create_progress_bar, get_pool_size, parse_manifest_line,
    read_manifest_file, read_public_key, report_duplicative_and_insert_nonce, send_check_message,
    send_pass_fail_check_message, write_check_from_channel, CheckMessage, ManifestLine,
    BITS_IN_BYTES, DEFAULT_MANIFEST_FILE_NAME, DEFAULT_PUBIC_KEY_FILE_NAME, END_MESSAGE,
    NO_OUTPUTFILE, PRINT_MESSAGE, PUBLICKEY_LENGTH_IN_BYTES, PWD, SEPARATOR_LINE,
    SIGNED_LENGTH_IN_BYTES, SIGN_HEADER_MESSAGE_COUNT, TOKEN_SEPARATOR,
};

use data_encoding::HEXUPPER;
use rayon::prelude::*;
use std::collections::HashMap;
use std::env;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, Command};
use indicatif::ProgressBar;

const NUMBER_OF_LINES_UNTIL_FILE_LEN_MESSAGE: usize = 6;

/// Build the command-line interface definition for `check_hash`.
fn build_cli() -> Command {
    Command::new("check_hash")
        .version("1.0.0")
        .author("Stephen Battista <stephen.battista@gmail.com>")
        .about("Verifies signed hash manifests for files")
        .arg(
            Arg::new("public")
                .short('u')
                .long("public")
                .value_name("FILE")
                .help("Public key file location. Default: Signpub.txt"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Manifest file location. Default: Manifest.txt"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file location. Default: STDIO"),
        )
        .arg(
            Arg::new("pool")
                .short('p')
                .long("pool")
                .value_name("#")
                .help("Thread pool size. Default: CPU cores"),
        )
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIRECTORY")
                .help("Directory to check. Default: current directory"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Print matches as well as failures")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("manifestonly")
                .short('m')
                .long("manifestonly")
                .help("Check manifest validity only, ignore -d option")
                .action(ArgAction::SetTrue),
        )
        .after_help("EXAMPLES:
    # Check manifest integrity only (no file verification)
    check_hash -i manifest.txt -m
    
    # Verify files in directory against manifest
    check_hash -i manifest.txt -d /data
    
    # Verbose mode - show all checks including successful ones
    check_hash -i manifest.txt -d /data -v
    
    # Save results to file
    check_hash -i manifest.txt -d /data -o results.txt
    
    # Use custom public key file
    check_hash -i manifest.txt -u MyKey.pub -d /data
    
    # Check with 4 threads and save verbose output
    check_hash -i manifest.txt -d /data -p 4 -v -o results.txt
    
    # Full example with all options
    check_hash -i docs_manifest.txt -u docs_key.pub -d /home/user/documents -p 8 -v -o verification.log

OUTPUT:
    Results show:
    - Success: Files matching manifest (in verbose mode)
    - Failure|file|reason: Files that don't match or are missing
    - Manifest tampering detection via signature verification

NOTES:
    - Checks file size, modification time, hash, and signature
    - Detects both file changes and manifest tampering
    - Use -m flag to only verify manifest signature without checking files
    - Progress bars are shown when outputting to a file
    - Thread pool size defaults to CPU core count if not specified or set to 0")
}

/// Configuration parsed from CLI arguments
struct Config {
    public_key_file: String,
    input_file: String,
    output_file: String,
    fileoutput: bool,
    poolnumber: usize,
    input_directory: String,
    verbose: bool,
    manifest_only: bool,
}

impl Config {
    /// Construct configuration from parsed CLI matches.
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let output_file = matches
            .get_one::<String>("output")
            .cloned()
            .unwrap_or_else(|| NO_OUTPUTFILE.to_string());
        let fileoutput = output_file != NO_OUTPUTFILE;

        let input_file = matches
            .get_one::<String>("input")
            .cloned()
            .unwrap_or_else(|| DEFAULT_MANIFEST_FILE_NAME.to_string());

        let public_key_file = matches
            .get_one::<String>("public")
            .map_or(DEFAULT_PUBIC_KEY_FILE_NAME.to_string(), Clone::clone);

        let input_directory = matches
            .get_one::<String>("directory")
            .map_or(PWD.to_string(), Clone::clone);

        Self {
            public_key_file,
            input_file,
            output_file,
            fileoutput,
            poolnumber: get_pool_size(
                matches
                    .get_one::<String>("pool")
                    .map_or("0", String::as_str),
            ),
            input_directory,
            verbose: matches.get_flag("verbose"),
            manifest_only: matches.get_flag("manifestonly"),
        }
    }

    /// Validate configuration and check that required files exist
    fn validate(&self) -> Result<(), String> {
        // Check manifest file exists
        if !std::path::Path::new(&self.input_file).exists() {
            return Err(format!(
                "Manifest file '{}' does not exist",
                self.input_file
            ));
        }
        if !std::path::Path::new(&self.input_file).is_file() {
            return Err(format!("'{}' is not a file", self.input_file));
        }

        // Try to read manifest file to check permissions
        if let Err(e) = std::fs::File::open(&self.input_file) {
            return Err(format!(
                "Cannot read manifest file '{}': {e}",
                self.input_file
            ));
        }

        // Check public key file exists
        if !std::path::Path::new(&self.public_key_file).exists() {
            return Err(format!(
                "Public key file '{}' does not exist",
                self.public_key_file
            ));
        }
        if !std::path::Path::new(&self.public_key_file).is_file() {
            return Err(format!("'{}' is not a file", self.public_key_file));
        }

        // Check input directory exists (unless manifest-only mode)
        if !self.manifest_only {
            let dir_path = std::path::Path::new(&self.input_directory);
            if !dir_path.exists() {
                return Err(format!(
                    "Directory '{}' does not exist",
                    self.input_directory
                ));
            }
            if !dir_path.is_dir() {
                return Err(format!("'{}' is not a directory", self.input_directory));
            }

            // Check if directory is readable
            if let Err(e) = std::fs::read_dir(&self.input_directory) {
                return Err(format!(
                    "Cannot read directory '{}': {e}",
                    self.input_directory
                ));
            }
        }

        // Validate output file can be created (if specified)
        if self.fileoutput {
            let output_path = std::path::Path::new(&self.output_file);

            // Check if parent directory exists and is writable
            if let Some(parent) = output_path.parent() {
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

            // Warn if output file already exists
            if output_path.exists() {
                eprintln!(
                    "Warning: Output file '{}' already exists and will be overwritten",
                    self.output_file
                );
            }
        }

        Ok(())
    }
}

/// Parse manifest headers and return the hasher config, streaming hasher, byte count, and algorithm name.
///
/// Reads and validates the manifest header lines (version, command, hash algorithm, etc.)
/// and initializes a streaming hasher for integrity verification.
///
/// # Arguments
///
/// * `vec_of_lines` - Mutable vector of manifest lines (headers are removed as processed)
/// * `fileoutput` - Whether to show progress updates
/// * `nonce_bar` - Progress bar to update during header parsing
///
/// # Returns
///
/// Tuple of (`HasherOptions`, `StreamingHasher`, `byte_count`, `algorithm_name`)
///
/// # Behavior
///
/// Removes header lines from `vec_of_lines` as they're processed and adds them
/// to the streaming hasher for manifest integrity verification.
fn parse_manifest_headers(
    vec_of_lines: &mut Vec<String>,
    fileoutput: bool,
    nonce_bar: &ProgressBar,
) -> (HasherOptions, hash_helper::StreamingHasher, usize, String) {
    let inc = || {
        if fileoutput {
            nonce_bar.inc(1);
        }
    };

    // Parse header lines
    let mut version_line = vec_of_lines.remove(0);
    inc();
    let mut command_line = vec_of_lines.remove(0);
    inc();
    let mut hash_line = vec_of_lines.remove(0);
    inc();

    // Extract hash algorithm
    let hash_algo = hash_line
        .split(TOKEN_SEPARATOR)
        .nth(1)
        .unwrap_or("256")
        .to_string();
    let hasher_option = HasherOptions::new(&hash_algo);

    // Initialize streaming hasher with header lines
    version_line += "\n";
    let mut hasher = hasher_option
        .clone()
        .multi_hash_update(version_line.as_bytes());
    let mut file_len = version_line.len();

    command_line += "\n";
    hasher = hasher.multi_hash_update(command_line.as_bytes());
    file_len += command_line.len();

    hash_line += "\n";
    hasher = hasher.multi_hash_update(hash_line.as_bytes());
    file_len += hash_line.len();

    // Process remaining header lines until separator
    loop {
        let mut line = vec_of_lines.remove(0);
        inc();
        if line == SEPARATOR_LINE {
            // Include separator in hash before breaking
            line += "\n";
            hasher = hasher.multi_hash_update(line.as_bytes());
            file_len += line.len();
            break;
        }
        line += "\n";
        hasher = hasher.multi_hash_update(line.as_bytes());
        file_len += line.len();
    }

    (hasher_option, hasher, file_len, hash_algo)
}

/// Parse file entries from manifest, checking for duplicate nonces.
///
/// Processes the file entry section of the manifest, detecting duplicate nonces
/// and building a map of file paths to their expected metadata.
///
/// # Arguments
///
/// * `vec_of_lines` - Mutable vector of manifest lines (entries are removed as processed)
/// * `hasher` - Streaming hasher to update with entry data
/// * `file_len` - Current byte count in manifest
/// * `fileoutput` - Whether to show progress updates
/// * `nonce_bar` - Progress bar to update during parsing
/// * `check_tx` - Channel for sending duplicate nonce warnings
///
/// # Returns
///
/// Tuple of (`manifest_map`, `updated_hasher`, `updated_byte_count`)
fn parse_manifest_entries(
    vec_of_lines: &mut Vec<String>,
    hasher: hash_helper::StreamingHasher,
    file_len: usize,
    fileoutput: bool,
    nonce_bar: &ProgressBar,
    check_tx: &mpsc::Sender<CheckMessage>,
) -> (
    HashMap<String, ManifestLine>,
    hash_helper::StreamingHasher,
    usize,
) {
    let mut manifest_map = HashMap::new();
    let mut nonces: HashMap<String, String> = HashMap::new();
    let mut hasher = hasher;
    let mut file_len = file_len;

    // Process separator line
    let mut line = vec_of_lines.remove(0);
    line += "\n";
    hasher = hasher.multi_hash_update(line.as_bytes());
    file_len += line.len();
    if fileoutput {
        nonce_bar.inc(1);
    }

    // Process file entries
    loop {
        let mut line = vec_of_lines.remove(0);
        if line == SEPARATOR_LINE {
            // Put separator back - we'll need it later
            vec_of_lines.insert(0, line);
            break;
        }

        let (file_name, manifest_struct) = parse_manifest_line(&line);
        report_duplicative_and_insert_nonce(
            &mut nonces,
            &manifest_struct.nonce,
            &file_name,
            check_tx,
        );
        manifest_map.insert(file_name, manifest_struct);

        line += "\n";
        hasher = hasher.multi_hash_update(line.as_bytes());
        file_len += line.len();
        if fileoutput {
            nonce_bar.inc(1);
        }
    }

    (manifest_map, hasher, file_len)
}

/// Verify manifest footer (length, hash, signature).
///
/// Validates the manifest's integrity by checking:
/// 1. File length matches computed byte count
/// 2. Manifest hash matches recomputed hash
/// 3. Ed25519 signature verifies correctly
///
/// # Arguments
///
/// * `vec_of_lines` - Remaining manifest lines (footer section)
/// * `hasher` - Streaming hasher with all manifest content
/// * `file_len` - Expected manifest byte count
/// * `public_key_bytes` - Ed25519 public key for signature verification
/// * `check_tx` - Channel for sending verification results
///
/// # Behavior
///
/// Sends pass/fail messages for each check (length, hash, signature) via channel.
fn verify_manifest_footer(
    vec_of_lines: &mut Vec<String>,
    mut hasher: hash_helper::StreamingHasher,
    mut file_len: usize,
    public_key_bytes: &[u8],
    check_tx: &mpsc::Sender<CheckMessage>,
) {
    // Skip separator and process remaining lines
    for _ in 0..=NUMBER_OF_LINES_UNTIL_FILE_LEN_MESSAGE {
        let mut line = vec_of_lines.remove(0);
        line += "\n";
        hasher = hasher.multi_hash_update(line.as_bytes());
        file_len += line.len();
    }

    // Verify file length
    let mut line = vec_of_lines.remove(0);

    let tokens: Vec<&str> = line.split(TOKEN_SEPARATOR).collect();
    let reported_len = tokens[1].trim();
    send_pass_fail_check_message(
        reported_len == format!("{file_len}"),
        format!("Correct|file length is|{file_len}\n"),
        format!("Failure|manifest length|{reported_len}|observed|{file_len}\n"),
        check_tx,
    );

    line += "\n";
    hasher = hasher.multi_hash_update(line.as_bytes());

    // Verify hash
    let digest = hasher.finish();
    let digest_text = HEXUPPER.encode(digest.as_ref());
    let line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = line.split(TOKEN_SEPARATOR).collect();
    send_pass_fail_check_message(
        tokens[1] == digest_text,
        format!("Correct|file hash is|{digest_text}\n"),
        format!(
            "Failure|manifest hash|{}|observed|{digest_text}\n",
            tokens[1]
        ),
        check_tx,
    );

    // Verify signature
    let line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = line.split(TOKEN_SEPARATOR).collect();

    let signature_bytes = HEXUPPER.decode(tokens[1].as_bytes()).unwrap_or_else(|why| {
        send_check_message(
            PRINT_MESSAGE,
            format!("Failure|couldn't decode hex signature|{why}\n"),
            false,
            check_tx,
        );
        vec![0u8; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES]
    });

    let mut sig_array = [0u8; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES];
    sig_array.copy_from_slice(&signature_bytes);

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
    match public_key.verify(digest_text.as_bytes(), &sig_array) {
        Ok(()) => send_check_message(
            PRINT_MESSAGE,
            "Correct|manifest signature verified.\n",
            false,
            check_tx,
        ),
        Err(_) => send_check_message(
            PRINT_MESSAGE,
            "Failure|manifest signature verification failed.\n",
            false,
            check_tx,
        ),
    }
}

/// Initialize environment: load public key, read manifest, and collect input files.
///
/// Performs initial setup by loading the public key from disk, reading the entire
/// manifest file into memory, and collecting files from the input directory.
///
/// # Arguments
///
/// * `config` - Configuration containing file paths and options
///
/// # Returns
///
/// Tuple of (`public_key_bytes`, `manifest_lines`, `input_files`)
///
/// # Panics
///
/// Panics if public key cannot be read or manifest file cannot be opened.
fn initialize_data(
    config: &Config,
) -> (
    [u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES],
    Vec<String>,
    Vec<String>,
) {
    let mut public_key_bytes = [0u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];
    read_public_key(&config.public_key_file, &mut public_key_bytes);

    let mut vec_of_lines: Vec<String> = Vec::new();
    read_manifest_file(&mut vec_of_lines, &config.input_file, config.fileoutput);

    let inputfiles = if config.manifest_only {
        Vec::new()
    } else {
        collect_files(&config.input_directory, config.fileoutput)
    };

    (public_key_bytes, vec_of_lines, inputfiles)
}

/// Parse manifest headers and entries, returning parsed structures and hash context.
///
/// Orchestrates parsing of both manifest headers and file entries with progress tracking.
///
/// # Arguments
///
/// * `vec_of_lines` - Manifest lines to parse
/// * `config` - Configuration containing display options
/// * `check_tx` - Channel for sending parse warnings/errors
///
/// # Returns
///
/// Tuple of (`hasher_options`, `manifest_map`, `streaming_hasher`, `byte_count`, `algorithm_name`)
fn process_and_parse_manifest(
    vec_of_lines: &mut Vec<String>,
    config: &Config,
    check_tx: &mpsc::Sender<CheckMessage>,
) -> (
    HasherOptions,
    HashMap<String, ManifestLine>,
    hash_helper::StreamingHasher,
    usize,
    String,
) {
    let bar_len = vec_of_lines
        .len()
        .saturating_sub(SIGN_HEADER_MESSAGE_COUNT + 10) as u64;
    let nonce_bar = create_progress_bar(bar_len, "Parsing manifest:", "green", config.fileoutput);

    let (hasher_option, hasher, file_len, hash_algo) =
        parse_manifest_headers(vec_of_lines, config.fileoutput, &nonce_bar);

    let (manifest_map, hasher, file_len) = parse_manifest_entries(
        vec_of_lines,
        hasher,
        file_len,
        config.fileoutput,
        &nonce_bar,
        check_tx,
    );

    if config.fileoutput {
        nonce_bar.finish();
    }

    (hasher_option, manifest_map, hasher, file_len, hash_algo)
}

/// Log initial execution information.
///
/// Sends diagnostic information about the verification run to the output channel.
///
/// # Arguments
///
/// * `args` - Command-line arguments used to invoke the program
/// * `now` - Start timestamp
/// * `config` - Configuration containing thread count and options
/// * `hash_algo` - Hash algorithm name from manifest
/// * `check_tx` - Channel for sending log messages
fn log_execution_info(
    args: &[String],
    now: &DateTime<Utc>,
    config: &Config,
    hash_algo: &str,
    check_tx: &mpsc::Sender<CheckMessage>,
) {
    send_check_message(
        PRINT_MESSAGE,
        format!("Command Line|{}\n", args.join(" ")),
        true,
        check_tx,
    );
    send_check_message(PRINT_MESSAGE, format!("Start time|{now}\n"), true, check_tx);
    send_check_message(
        PRINT_MESSAGE,
        format!("Threads|{}\n", config.poolnumber),
        true,
        check_tx,
    );
    send_check_message(
        PRINT_MESSAGE,
        format!("Hash algorithm|{hash_algo}\n"),
        true,
        check_tx,
    );
    send_check_message(PRINT_MESSAGE, "Signature|ED25519\n", true, check_tx);
}

/// Spawn writer thread responsible for emitting results.
///
/// Creates a background thread that receives check messages and writes them
/// to either a file or stdout.
///
/// # Arguments
///
/// * `config` - Configuration containing output settings
/// * `progress_bar` - Progress bar to update as checks complete
/// * `check_rx` - Channel receiver for check messages
///
/// # Returns
///
/// Join handle for the writer thread.
fn spawn_writer_thread(
    config: &Config,
    progress_bar: ProgressBar,
    check_rx: mpsc::Receiver<CheckMessage>,
) -> thread::JoinHandle<()> {
    let verbose = config.verbose;
    let output_file = config.output_file.clone();
    let fileoutput = config.fileoutput;

    thread::spawn(move || {
        write_check_from_channel(verbose, &check_rx, &output_file, fileoutput, &progress_bar);
    })
}

/// Execute parallel checks and return any remaining manifest entries.
///
/// Verifies files against manifest entries in parallel using Rayon.
/// In manifest-only mode, verifies signatures without checking actual files.
///
/// # Arguments
///
/// * `config` - Configuration containing mode and thread settings
/// * `inputfiles` - Files found in input directory
/// * `manifest_map` - Expected file metadata from manifest
/// * `hasher_option` - Hashing algorithm configuration
/// * `public_key_bytes` - Ed25519 public key for signature verification
/// * `check_tx` - Channel for sending verification results
///
/// # Returns
///
/// Remaining manifest entries that weren't found in the input directory.
fn execute_parallel_checks(
    config: &Config,
    inputfiles: &[String],
    manifest_map: HashMap<String, ManifestLine>,
    hasher_option: &HasherOptions,
    public_key_bytes: &[u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES],
    check_tx: &mpsc::Sender<CheckMessage>,
) -> HashMap<String, ManifestLine> {
    let manifest_map = Arc::new(Mutex::new(manifest_map));

    if config.manifest_only {
        // Collect entries first to avoid holding lock during iteration
        let entries: Vec<_> = manifest_map.lock().unwrap().drain().collect();

        entries.par_iter().for_each(|(path, manifest)| {
            check_line(
                path,
                hasher_option,
                manifest,
                public_key_bytes,
                check_tx,
                true,
            );
        });
    } else {
        inputfiles.par_iter().for_each(|file| {
            let manifest_opt = manifest_map.lock().unwrap().remove(file);

            match manifest_opt {
                Some(manifest) => {
                    check_line(
                        file,
                        hasher_option,
                        &manifest,
                        public_key_bytes,
                        check_tx,
                        false,
                    );
                }
                None => send_check_message(
                    PRINT_MESSAGE,
                    format!("Failure|{file}|not in manifest\n"),
                    false,
                    check_tx,
                ),
            }
        });
    }

    Arc::try_unwrap(manifest_map).unwrap().into_inner().unwrap()
}

/// Report missing files and verify manifest footer.
///
/// Reports any files that were in the manifest but not found on disk,
/// then verifies the manifest's integrity (length, hash, signature).
///
/// # Arguments
///
/// * `manifest_map` - Remaining manifest entries (files not found)
/// * `vec_of_lines` - Remaining manifest lines (footer)
/// * `hasher` - Streaming hasher with manifest content
/// * `file_len` - Manifest byte count
/// * `public_key_bytes` - Ed25519 public key
/// * `check_tx` - Channel for sending results and end signal
fn finalize_and_verify(
    manifest_map: HashMap<String, ManifestLine>,
    vec_of_lines: &mut Vec<String>,
    hasher: hash_helper::StreamingHasher,
    file_len: usize,
    public_key_bytes: &[u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES],
    check_tx: &mpsc::Sender<CheckMessage>,
) {
    for (path, _) in manifest_map {
        send_check_message(
            PRINT_MESSAGE,
            format!("Failure|{path}|in manifest but not found\n"),
            false,
            check_tx,
        );
    }

    verify_manifest_footer(vec_of_lines, hasher, file_len, public_key_bytes, check_tx);
    send_check_message(END_MESSAGE, "End", false, check_tx);
}

/// Entry point for verifying manifests and files against signed hashes.
fn main() {
    let now: DateTime<Utc> = Utc::now();
    let args: Vec<String> = env::args().collect();
    let config = Config::from_matches(&build_cli().get_matches());

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    // Initialize key, manifest, and file list
    let (public_key_bytes, mut vec_of_lines, inputfiles) = initialize_data(&config);

    // Setup channel and configure rayon thread pool
    let (check_tx, check_rx) = mpsc::channel();
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(config.poolnumber)
        .build_global()
    {
        eprintln!("Warning: Failed to configure thread pool: {e}. Using default configuration.");
    }
    let (hasher_option, manifest_map, hasher, file_len, hash_algo) =
        process_and_parse_manifest(&mut vec_of_lines, &config, &check_tx);

    log_execution_info(&args, &now, &config, &hash_algo, &check_tx);

    // Setup verification progress bar and writer thread
    let check_prefix = if config.manifest_only {
        "Checking signatures:"
    } else {
        "Checking files:"
    };
    let bar_len = vec_of_lines
        .len()
        .saturating_sub(SIGN_HEADER_MESSAGE_COUNT + 10) as u64;
    let progress_bar = create_progress_bar(bar_len, check_prefix, "yellow", config.fileoutput);
    let writer_child = spawn_writer_thread(&config, progress_bar, check_rx);

    let remaining_manifest = execute_parallel_checks(
        &config,
        &inputfiles,
        manifest_map,
        &hasher_option,
        &public_key_bytes,
        &check_tx,
    );

    finalize_and_verify(
        remaining_manifest,
        &mut vec_of_lines,
        hasher,
        file_len,
        &public_key_bytes,
        &check_tx,
    );

    // Wait for writer thread to finish and handle any errors
    if let Err(e) = writer_child.join() {
        eprintln!("Error: Writer thread panicked: {e:?}");
        std::process::exit(1);
    }
}
