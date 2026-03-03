use crate::hash_helper::{hash_file, HasherOptions};

use chrono::{DateTime, Utc};
use data_encoding::HEXUPPER;
use indicatif::HumanBytes;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use rand::prelude::ThreadRng;
use rand::RngExt;
use ring::signature::KeyPair;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::time::Instant;

pub const SIGN_HEADER_MESSAGE_COUNT: usize = 8;
#[allow(dead_code)]
pub const PRIVATEKEY_LENGTH_IN_BYTES: usize = 664;
pub const PUBLICKEY_LENGTH_IN_BYTES: usize = 256;
pub const SIGNED_LENGTH_IN_BYTES: usize = 512;
pub const NONCE_LENGTH_IN_BYTES: usize = 1024;
pub const BITS_IN_BYTES: usize = 8;
pub const TOKEN_SEPARATOR: &str = "|";
pub const PRIVATE_KEY_STRING_ED25519: &str = "Private ED25519";
// Note: Memory-mapped I/O (memmap2) is used for files ≥16KB for optimal performance
pub const SEPARATOR_LINE: &str =
    "********************************************************************************"; //80 stars
const NO_HASH: &str = "0";
const NO_TIME: &str = "00/00/0000 00:00:00";
pub const PUBIC_KEY_STRING_ED25519: &str = "Public ED25519";
#[allow(dead_code)]
pub const DEFAULT_PUBIC_KEY_FILE_NAME: &str = "Signpub.txt";
#[allow(dead_code)]
pub const DEFAULT_MANIFEST_FILE_NAME: &str = "Manifest.txt";
#[allow(dead_code)]
pub const NO_OUTPUTFILE: &str = "|||";
#[allow(dead_code)]
pub const PWD: &str = ".";
#[allow(dead_code)]
pub const PRINT_MESSAGE: u8 = 0;
#[allow(dead_code)]
const TICK_MESSAGE: u8 = 1;
#[allow(dead_code)]
pub const END_MESSAGE: u8 = 2;
/// Message used for reporting signing progress.
///
/// Contains text to display and file length for progress calculation.
#[allow(dead_code)]
pub struct SignMessage {
    /// The text message to display
    pub text: String,
    /// The length of the file being processed in bytes
    pub file_len: u64,
}
/// Message used for reporting verification results.
///
/// Contains the type of check, message text, and verbosity flag.
#[allow(dead_code)]
pub struct CheckMessage {
    /// Type of check being performed (`PRINT_MESSAGE`, `TICK_MESSAGE`, or `END_MESSAGE`)
    pub check_type: u8,
    /// The text message to display
    pub text: String,
    /// Whether to display verbose output
    pub verbose: bool,
}

/// Output destination for writing data.
///
/// Supports either writing to a file or accumulating in a string buffer.
pub enum Whereoutput {
    /// Write to an open file handle
    FilePointer(File),
    /// Accumulate text in a string buffer
    StringText(String),
}
/// Parsed components of a manifest file entry.
///
/// Each line in a manifest contains file metadata and cryptographic data.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ManifestLine {
    /// Type of file entry ("File", "Directory", etc.)
    pub file_type: String,
    /// Size of the file in bytes
    pub bytes: String,
    /// Timestamp when the file was last modified
    pub time: String,
    /// Cryptographic hash of the file contents
    pub hash: String,
    /// Random nonce for preventing precomputed attacks
    pub nonce: String,
    /// Ed25519 signature of the entry
    pub sign: String,
}

/// Reports duplicate nonces and inserts new nonces into the tracking map.
///
/// # Arguments
///
/// * `nonces` - `HashMap` tracking nonce-to-filename mappings
/// * `nonce` - The nonce string to check and insert
/// * `file_name_line` - The filename associated with this nonce
/// * `check_tx` - Channel sender for reporting check messages
///
/// # Behavior
///
/// If the nonce already exists, sends a failure message indicating which
/// files share the same nonce. Otherwise, inserts the nonce silently.
#[allow(dead_code)]
pub fn report_duplicative_and_insert_nonce<S: BuildHasher>(
    nonces: &mut HashMap<String, String, S>,
    nonce: &str,
    file_name_line: &str,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    match nonces.insert(nonce.to_string(), file_name_line.to_string()) {
        None => (),
        Some(answer) => {
            send_check_message(
                PRINT_MESSAGE,
                format!("Failure|{nonce}|and|{answer}|share the same nonce.\n"),
                false,
                check_tx,
            );
        }
    }
}

/// Generates a unique cryptographic nonce that hasn't been used before.
///
/// # Arguments
///
/// * `nonce_bytes` - Mutable array to fill with the generated nonce
/// * `nonces` - `HashMap` tracking previously used nonces
/// * `rng` - Thread-local random number generator
///
/// # Behavior
///
/// Repeatedly generates random bytes until a unique nonce is found.
/// If a duplicate is detected, prints a warning and regenerates.
/// Inserts the new nonce into the tracking map.
#[allow(dead_code)]
pub fn provide_unique_nonce<S: BuildHasher>(
    nonce_bytes: &mut [u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES],
    nonces: &mut HashMap<[u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES], i32, S>,
    mut rng: ThreadRng,
) {
    let mut duplicate = true;
    while duplicate {
        for item in nonce_bytes.iter_mut() {
            *item = rng.random();
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

/// Receives check messages from a channel and writes them to output.
///
/// # Arguments
///
/// * `verbose` - If true, prints all messages including verbose ones
/// * `check_rx` - Channel receiver for incoming check messages
/// * `output_file` - Path to output file, or special marker for STDIO
/// * `fileoutput` - Whether output is to a file (vs STDIO)
/// * `progress_bar` - Progress bar to update on TICK messages
///
/// # Behavior
///
/// Continuously receives messages until `END_MESSAGE` is received.
/// `TICK_MESSAGE` updates progress bar, other messages are written based
/// on verbose flag. Finishes progress bar when complete.
///
/// # Panics
///
/// Panics if:
/// - Output file cannot be created
/// - Channel receive operation fails
#[allow(dead_code)]
pub fn write_check_from_channel(
    verbose: bool,
    check_rx: &std::sync::mpsc::Receiver<CheckMessage>,
    output_file: &str,
    fileoutput: bool,
    progress_bar: &ProgressBar,
) {
    let mut message: CheckMessage;
    let mut wherefile: Whereoutput;
    let filepointer: File;
    if fileoutput {
        filepointer = match File::create(output_file) {
            Ok(filepointer) => filepointer,
            Err(why) => panic!(
                "couldn't create check file requested at|{}|{}",
                output_file, why
            ),
        };
        wherefile = Whereoutput::FilePointer(filepointer);
    } else {
        wherefile = Whereoutput::StringText("STDIO".to_owned());
    }
    message = check_rx.recv().unwrap();
    while message.check_type != END_MESSAGE {
        if message.check_type == TICK_MESSAGE {
            if fileoutput {
                progress_bar.inc(1);
            }
        } else if verbose || !(message.verbose) {
            write_line(&mut wherefile, &message.text);
        }
        message = check_rx.recv().unwrap();
    }
    if fileoutput {
        progress_bar.finish();
    }
}

/// Writes a line of data to either a file or STDIO.
///
/// # Arguments
///
/// * `wherefile` - Output destination (file or STDIO)
/// * `data` - String data to write
///
/// # Panics
///
/// Panics if writing to file fails.
pub fn write_line(wherefile: &mut Whereoutput, data: &str) {
    match wherefile {
        Whereoutput::FilePointer(ref mut file) => {
            if let Err(why) = file.write_all(data.as_bytes()) {
                panic!("Couldn't write|{}|to the manifest file|{}.", data, why);
            }
        }
        Whereoutput::StringText(_string) => {
            print!("{data}");
        }
    }
}

/// Context for writing operations containing shared configuration.
///
/// Holds references to output file path, progress tracking, and output mode.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct WriterContext<'a> {
    /// Path to the manifest file being written
    pub manifest_file: &'a str,
    /// Progress bar for tracking operation status
    pub progress_bar: &'a ProgressBar,
    /// Whether to write output to file (true) or collect in memory (false)
    pub file_output: bool,
}

/// Receives manifest entries from workers, writes to file, and signs the manifest.
///
/// # Arguments
///
/// * `num_lines` - Expected number of messages to receive (headers + entries)
/// * `hasher_opts` - Hashing options for computing manifest integrity hash
/// * `private_key_bytes` - Ed25519 private key for signing
/// * `rx` - Channel receiver for manifest messages from workers
/// * `start` - Start time for duration calculation
/// * `ctx` - Writer context containing file path and progress bar
///
/// # Behavior
///
/// Receives all manifest entries, writes them to file, computes statistics
/// (duration, file count, total bytes, speed), generates nonce, computes
/// manifest hash, and signs it with private key. Updates progress bar as
/// entries are processed.
///
/// # Panics
///
/// Panics if:
/// - Manifest file cannot be created
/// - Writing to file fails
/// - Channel receive operation fails
#[allow(dead_code)]
#[allow(clippy::too_many_lines)]
pub fn write_manifest_from_channel(
    num_lines: usize,
    hasher_opts: HasherOptions,
    private_key_bytes: &[u8],
    rx: &std::sync::mpsc::Receiver<SignMessage>,
    start: Instant,
    ctx: WriterContext<'_>,
) {
    let mut byte_count = 0;
    let mut total_file_len: u64 = 0;

    let wherefile = if ctx.manifest_file == "|||" {
        Whereoutput::StringText("STDIO".to_owned())
    } else {
        let fp = File::create(ctx.manifest_file).unwrap_or_else(|why| {
            panic!(
                "couldn't create manifest file requested at|{}|{}",
                ctx.manifest_file, why
            )
        });
        Whereoutput::FilePointer(fp)
    };
    let mut wherefile = wherefile;

    // Process first message to initialize streaming hasher
    let message = rx.recv().unwrap();
    let data = message.text.clone();
    byte_count += data.len();
    let mut hasher = hasher_opts.multi_hash_update(data.as_bytes());
    total_file_len += message.file_len;
    write_line(&mut wherefile, &data);

    // Process remaining messages
    for x in 1..num_lines {
        let message = rx.recv().unwrap();
        let data = message.text.clone();
        byte_count += data.len();
        hasher = hasher.multi_hash_update(data.as_bytes());
        total_file_len += message.file_len;
        write_line(&mut wherefile, &data);
        if x > SIGN_HEADER_MESSAGE_COUNT && ctx.file_output {
            ctx.progress_bar.inc(1);
        }
    }

    let mut data = SEPARATOR_LINE.to_owned() + "\n";
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());

    write_line(&mut wherefile, &data);

    let duration = start.elapsed();
    let processed_files = num_lines.saturating_sub(SIGN_HEADER_MESSAGE_COUNT);
    let processed_files_u64 = u64::try_from(processed_files).unwrap_or(u64::MAX);
    let duration_ms = duration.as_millis();
    let duration_ms_u64 = u64::try_from(duration_ms).unwrap_or(u64::MAX);
    let bytes_per_second = if duration_ms_u64 == 0 {
        0
    } else {
        total_file_len.saturating_mul(1_000) / duration_ms_u64
    };
    let avg_bytes = if processed_files_u64 == 0 {
        0
    } else {
        total_file_len / processed_files_u64
    };
    data = format!("Time elapsed was|{duration:?}\n");
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    data = format!("Total number of files hashed is|{processed_files}\n");
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    let human_total_file_len = HumanBytes(total_file_len);
    data = format!("Total byte count of files in bytes is|{human_total_file_len}\n");
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    let human_bytes_per_second = HumanBytes(bytes_per_second);
    data = format!("Speed is|{human_bytes_per_second}ps\n");
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    let human_avg_bytes = HumanBytes(avg_bytes);
    data = format!("Average byte count per file in bytes is|{human_avg_bytes}\n");
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    let mut nonce_bytes: [u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES] =
        [0; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut rng = rand::rng();

    for item in &mut nonce_bytes {
        *item = rng.random();
    }
    data = format!("Nonce for file|{}\n", HEXUPPER.encode(&nonce_bytes));
    byte_count += data.len();
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    data = format!("Sum of size of file so far is|{byte_count:?}\n");
    hasher = hasher.multi_hash_update(data.as_bytes());
    write_line(&mut wherefile, &data);

    let digest = hasher.finish();
    data = format!("Hash of file so far|{}\n", HEXUPPER.encode(digest.as_ref()));
    write_line(&mut wherefile, &data);

    let signature = sign_data(&HEXUPPER.encode(digest.as_ref()), private_key_bytes);
    data = format!(
        "Signature of hash|{}\n",
        HEXUPPER.encode(signature.as_ref())
    );
    write_line(&mut wherefile, &data);
    if ctx.file_output {
        ctx.progress_bar.finish();
    }
}

/// Signs data using Ed25519 private key.
///
/// # Arguments
///
/// * `data` - String data to sign
/// * `private_key_bytes` - PKCS#8 encoded Ed25519 private key bytes
///
/// # Returns
///
/// Ed25519 signature over the data.
///
/// # Panics
///
/// Panics if the private key cannot be loaded from PKCS#8 format.
#[allow(dead_code)]
fn sign_data(data: &str, private_key_bytes: &[u8]) -> ring::signature::Signature {
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(private_key_bytes)
        .unwrap_or_else(|why| panic!("Couldn't load key pair from PKCS8 data.|{}", why));
    key_pair.sign(data.as_bytes())
}

/// Reads an Ed25519 private key from a YAML file.
///
/// # Arguments
///
/// * `private_key_bytes` - Buffer to fill with the decoded private key
/// * `private_key_file` - Path to YAML file containing hex-encoded private key
///
/// # Panics
///
/// Panics if file cannot be opened, YAML parsing fails, or hex decoding fails.
///
/// # Examples
///
/// ```no_run
/// use signhash::read_private_key;
/// let mut key_bytes = [0u8; 85];
/// read_private_key(&mut key_bytes, "Signpri.txt");
/// ```
#[allow(dead_code)]
pub fn read_private_key(private_key_bytes: &mut [u8], private_key_file: &str) {
    let mut file = match File::open(private_key_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "Couldn't open private key file named|{}|{}",
            private_key_file, why
        ),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read private key file named|{}|{}",
            private_key_file, why
        ),
    }
    let deserialized_map: BTreeMap<String, String> = match serde_yaml::from_str(&contents) {
        Ok(deserialized_map) => deserialized_map,
        Err(why) => panic!(
            "Couldn't parse private key YAML file in|{}|{}",
            private_key_file, why
        ),
    };
    let local_key = match HEXUPPER.decode(deserialized_map[PRIVATE_KEY_STRING_ED25519].as_bytes()) {
        Ok(local_key) => local_key,
        Err(why) => panic!("Couldn't decode hex encoded private key|{}", why),
    };
    private_key_bytes[..].clone_from_slice(&local_key[..]);
}

/// Reads and returns the contents of a header file.
///
/// # Arguments
///
/// * `header_file` - Path to the header file to read
///
/// # Returns
///
/// Contents of the header file as a String.
///
/// # Panics
///
/// Panics if file cannot be opened or read.
#[allow(dead_code)]
#[must_use]
pub fn dump_header(header_file: &str) -> String {
    let mut file = match File::open(header_file) {
        Ok(file) => file,
        Err(why) => panic!("Couldn't open header file named|{}|{}", header_file, why),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!("Couldn't read header file named|{}|{}", header_file, why),
    }
    contents
}

/// Computes hash digest of data from a reader using streaming approach.
///
/// # Arguments
///
/// * `reader` - Any type implementing Read trait (file, buffer, etc.)
/// * `hasher_opts` - Hashing options specifying algorithm and parameters
///
/// # Returns
///
/// Hash digest as a vector of bytes.
///
/// # Panics
///
/// Panics if reading from the reader fails.
///
/// # Examples
///
/// ```no_run
/// use signhash::{HasherOptions, var_digest};
/// use std::fs::File;
/// let file = File::open("data.bin").unwrap();
/// let opts = HasherOptions::new("256");
/// let digest = var_digest(file, opts);
/// ```
#[allow(dead_code)]
pub fn var_digest<R: Read>(mut reader: R, hasher_opts: HasherOptions) -> Vec<u8> {
    // Use adaptive buffer sizing for better performance
    // For generic readers, use 256KB as a reasonable default
    const ADAPTIVE_BUFFER_SIZE: usize = 256 * 1024;
    let mut buffer = vec![0_u8; ADAPTIVE_BUFFER_SIZE];

    // Read first chunk to initialize streaming hasher
    let count = match reader.read(&mut buffer) {
        Ok(count) => count,
        Err(why) => panic!("Couldn't load data from file to hash|{}", why),
    };
    if count == 0 {
        return hasher_opts.finish();
    }
    let mut hasher = hasher_opts.multi_hash_update(&buffer[..count]);

    // Read remaining chunks
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(why) => panic!("Couldn't load data from file to hash|{}", why),
        };
        if count == 0 {
            break;
        }
        hasher = hasher.multi_hash_update(&buffer[..count]);
    }
    hasher.finish()
}

/// Verifies a file against its manifest entry and signature.
///
/// # Arguments
///
/// * `path` - File path to verify
/// * `hasher` - Hashing options to use for computing file hash
/// * `manifest_struct` - Expected file metadata from manifest
/// * `public_key_bytes` - Ed25519 public key for signature verification
/// * `check_tx` - Channel sender for reporting check results
/// * `manifest_only` - If true, only verify signature without checking actual file
///
/// # Behavior
///
/// Compares file length, modification time, type, and hash against manifest.
/// Verifies Ed25519 signature over the manifest line. Sends success/failure
/// messages via channel for each check. Handles symlinks and missing files.
///
/// # Panics
///
/// Panics if:
/// - File metadata operations fail unexpectedly
/// - Hash computation encounters I/O errors
/// - Signature verification fails due to key format issues
/// - Channel send operations fail
#[allow(dead_code)]
#[allow(clippy::too_many_lines)]
pub fn check_line(
    path: &str,
    hasher: &HasherOptions,
    manifest_struct: &ManifestLine,
    public_key_bytes: &[u8],
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
    manifest_only: bool,
) {
    let line_type: String;
    let data: String;
    let digest_str: String;
    if manifest_only {
        data = format!(
            "{}|{}|{}|{}|{}|{}",
            manifest_struct.file_type.as_str(),
            &path,
            manifest_struct.bytes.as_str(),
            manifest_struct.time.as_str(),
            manifest_struct.hash.as_str(),
            manifest_struct.nonce.as_str()
        );
    } else {
        match fs::metadata(path) {
            Err(_why) => {
                data = format!(
                    "{}|{}|{}|{}|{}|{}",
                    "Bad-symlink",
                    &path,
                    0,
                    NO_TIME,
                    NO_HASH,
                    manifest_struct.nonce.as_str()
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
                    filelen == manifest_struct.bytes.as_str(),
                    format!("Correct|{path}|File length check passed.\n"),
                    format!(
                        "Failure|{}|{}|{}|File len check failed.\n",
                        &path, manifest_struct.bytes, filelen
                    ),
                    check_tx,
                );

                let datetime = match metadata.modified() {
                    Err(why) => panic!("Couldn't load datetime from|{} data|{}", &path, why),
                    Ok(datetime) => datetime,
                };
                let datetime: DateTime<Utc> = datetime.into();
                let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

                send_pass_fail_check_message(
                    datetime_string == manifest_struct.time.as_str(),
                    format!("Correct|{path}|Date check passed.\n"),
                    format!(
                        "Failure|{}|{}|{}|File date check failed.\n",
                        &path, manifest_struct.time, datetime_string
                    ),
                    check_tx,
                );

                if metadata.is_dir() {
                    line_type = format!("Dir{postfix}");
                    digest_str = NO_HASH.to_string();
                } else {
                    if metadata.is_file() {
                        line_type = format!("File{postfix}");
                    } else {
                        line_type = format!("Unknown{postfix}");
                    }
                    match File::open(path) {
                        Ok(input) => input,
                        Err(why) => panic!("Couldn't open file|{}|{}", &path, why),
                    };
                    let digest = hash_file(hasher, OsStr::new(&path));
                    digest_str = HEXUPPER.encode(digest.as_ref());
                }
                send_pass_fail_check_message(
                    line_type == manifest_struct.file_type.as_str(),
                    format!("Correct|{path}|File type check passed.\n"),
                    format!(
                        "Failure|{}|File type check failed|{}|{}\n",
                        &path, manifest_struct.file_type, line_type
                    ),
                    check_tx,
                );

                send_pass_fail_check_message(
                    digest_str == manifest_struct.hash.as_str(),
                    format!("Correct|{path}|Hash check passed.\n"),
                    format!(
                        "Failure|{}|Hash check failed|{}|{}.\n",
                        &path, manifest_struct.hash, digest_str
                    ),
                    check_tx,
                );
                data = format!(
                    "{}|{}|{}|{}|{}|{}",
                    manifest_struct.file_type.as_str(),
                    &path,
                    manifest_struct.bytes.as_str(),
                    manifest_struct.time.as_str(),
                    manifest_struct.hash.as_str(),
                    manifest_struct.nonce.as_str()
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
            vec![0; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES]
        }
    };
    let mut signature_key_bytes: [u8; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES] =
        [0; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES];

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

/// Creates a signed manifest entry for a file.
///
/// # Arguments
///
/// * `path` - File path to create entry for
/// * `hasher` - Hashing options for computing file hash
/// * `nonce_bytes` - Cryptographic nonce for uniqueness
/// * `private_key_bytes` - Ed25519 private key for signing
/// * `sign_tx` - Channel sender for transmitting manifest entry
///
/// # Behavior
///
/// Collects file metadata (type, size, modification time), computes hash,
/// formats manifest line with nonce, signs it with Ed25519, and sends via
/// channel. Handles files, directories, symlinks, and bad symlinks.
///
/// # Panics
///
/// Panics if:
/// - File metadata retrieval fails unexpectedly
/// - Hash computation encounters I/O errors
/// - `DateTime` conversion fails
/// - Signing operation fails due to key format issues
/// - Channel send operations fail
#[allow(dead_code)]
pub fn create_line(
    path: &str,
    hasher: &HasherOptions,
    nonce_bytes: &[u8],
    private_key_bytes: &[u8],
    sign_tx: &std::sync::mpsc::Sender<SignMessage>,
) {
    let line_type: String;
    let mut data: String;
    let mut filelen: u64 = 0;

    match fs::metadata(path) {
        Err(_why) => {
            data = format!(
                "{}|{}|{}|{}|{}|{}",
                "Bad-symlink",
                &path,
                filelen,
                NO_TIME,
                NO_HASH,
                HEXUPPER.encode(nonce_bytes)
            );
        }
        Ok(metadata) => {
            filelen = metadata.len();
            let datetime = match metadata.modified() {
                Err(why) => panic!("Couldn't load datetime from|{}|{}", &path, why),
                Ok(datetime) => datetime,
            };
            let metadata2 = fs::symlink_metadata(path).unwrap();
            let postfix = if metadata2.file_type().is_symlink() {
                "-symlink"
            } else {
                ""
            };
            let datetime: DateTime<Utc> = datetime.into();
            let digest_str: String;
            if metadata.is_dir() {
                line_type = format!("Dir{postfix}");
                digest_str = NO_HASH.to_string();
            } else if metadata.is_file() {
                match File::open(path) {
                    Ok(input) => input,
                    Err(why) => panic!("Couldn't open file|{}|{}", &path, why),
                };
                let digest = hash_file(hasher, OsStr::new(&path));
                digest_str = HEXUPPER.encode(digest.as_ref());
                line_type = format!("File{postfix}");
            } else {
                line_type = format!("Other{postfix}");
                digest_str = NO_HASH.to_string();
            }

            data = format!(
                "{}|{}|{}|{}|{}|{}",
                line_type,
                &path,
                filelen,
                datetime.format("%d/%m/%Y %T"),
                digest_str,
                HEXUPPER.encode(nonce_bytes)
            );
        }
    }
    let signature: ring::signature::Signature = sign_data(&data, private_key_bytes);
    data = format!("{}|{}\n", data, HEXUPPER.encode(signature.as_ref()));

    send_sign_message(data, filelen, sign_tx);
}

/// Generates a new Ed25519 key pair.
///
/// # Arguments
///
/// * `public_key_bytes` - Buffer to fill with public key (32 bytes)
/// * `private_key_bytes` - Buffer to fill with PKCS#8 private key (85 bytes)
///
/// # Panics
///
/// Panics if key generation or PKCS#8 encoding fails.
///
/// # Examples
///
/// ```no_run
/// use signhash::create_keys;
/// let mut pub_key = [0u8; 32];
/// let mut priv_key = [0u8; 85];
/// create_keys(&mut pub_key, &mut priv_key);
/// ```
#[allow(dead_code)]
pub fn create_keys(public_key_bytes: &mut [u8], private_key_bytes: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng) {
        Err(x) => panic!("Couldn't create pks8 key|{}", x),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
        Err(x) => panic!("Couldn't create key pair from pks8 key|{}", x),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    public_key_bytes[..].clone_from_slice(key_pair.public_key().as_ref());
    private_key_bytes[..].clone_from_slice(pkcs8_bytes.as_ref());
}

/// Writes a key to a YAML file with hex encoding.
///
/// # Arguments
///
/// * `public_key_bytes` - Key bytes to write
/// * `pubic_key_file` - Path to output YAML file
/// * `key_name` - YAML field name for the key
///
/// # Panics
///
/// Panics if YAML serialization or file writing fails.
///
/// # Examples
///
/// ```no_run
/// use signhash::write_key;
/// let pub_key = [0u8; 32];
/// write_key(&pub_key, "Signpub.txt", "ED25519_PUBLIC_KEY");
/// ```
#[allow(dead_code)]
pub fn write_key(public_key_bytes: &[u8], pubic_key_file: &str, key_name: &str) {
    let mut map = BTreeMap::new();
    map.insert(key_name.to_string(), HEXUPPER.encode(public_key_bytes));
    let s = match serde_yaml::to_string(&map) {
        Ok(s) => s,
        Err(x) => panic!("Couldn't create YAML string for|{}|key|{}", key_name, x),
    };
    let mut file = match File::create(pubic_key_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "couldn't create|{} key at|{}|{}",
            key_name, pubic_key_file, why
        ),
    };
    match file.write_all(s.as_bytes()) {
        Ok(()) => (),
        Err(why) => panic!(
            "Couldn't write to|{} key to|{}|{}",
            key_name, pubic_key_file, why
        ),
    }
}

/// Reads an Ed25519 public key from a YAML file.
///
/// # Arguments
///
/// * `public_key_file` - Path to YAML file containing hex-encoded public key
/// * `public_key_bytes` - Buffer to fill with decoded public key (32 bytes)
///
/// # Panics
///
/// Panics if file cannot be opened, YAML parsing fails, or hex decoding fails.
///
/// # Examples
///
/// ```no_run
/// use signhash::read_public_key;
/// let mut pub_key = [0u8; 32];
/// read_public_key("Signpub.txt", &mut pub_key);
/// ```
#[allow(dead_code)]
pub fn read_public_key(public_key_file: &str, public_key_bytes: &mut [u8]) {
    let mut file = match File::open(public_key_file) {
        Ok(filepointer) => filepointer,
        Err(why) => panic!(
            "Couldn't find public key file requested at|{}|{}",
            public_key_file, why
        ),
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read from public key file requested at|{}|{}",
            public_key_file, why
        ),
    }
    let deserialized_map: BTreeMap<String, String> = match serde_yaml::from_str(&contents) {
        Ok(deserialized_map) => deserialized_map,
        Err(why) => panic!(
            "Couldn't parse public key from YAML file requested at|{}|{}",
            public_key_file, why
        ),
    };
    let local_key = match HEXUPPER.decode(deserialized_map[PUBIC_KEY_STRING_ED25519].as_bytes()) {
        Ok(local_key) => local_key,
        Err(why) => panic!(
            "Couldn't decode hex from public key file requested at|{}|{}",
            public_key_file, why
        ),
    };
    public_key_bytes[..].clone_from_slice(&local_key[..]);
}

/// Writes both public and private keys to separate YAML files.
///
/// # Arguments
///
/// * `public_key_bytes` - Public key bytes (32 bytes)
/// * `private_key_bytes` - Private key bytes in PKCS#8 format (85 bytes)
/// * `public_key_file` - Path to public key output file
/// * `private_key_file` - Path to private key output file
///
/// # Examples
///
/// ```no_run
/// use signhash::write_keys;
/// let pub_key = [0u8; 32];
/// let priv_key = [0u8; 85];
/// write_keys(&pub_key, &priv_key, "Signpub.txt", "Signpri.txt");
/// ```
#[allow(dead_code)]
pub fn write_keys(
    public_key_bytes: &[u8],
    private_key_bytes: &[u8],
    public_key_file: &str,
    private_key_file: &str,
) {
    write_key(public_key_bytes, public_key_file, PUBIC_KEY_STRING_ED25519);
    write_key(
        private_key_bytes,
        private_key_file,
        PRIVATE_KEY_STRING_ED25519,
    );
}

/// Writes manifest header information to the signing channel.
///
/// # Arguments
///
/// * `sign_tx` - Channel sender for transmitting header lines
/// * `inputhash` - Hash algorithm name (e.g., "blake3", "256")
/// * `command_line` - Command line used to invoke the program
/// * `header_file` - Path to optional header file, or "|||" for none
/// * `now` - Current timestamp
/// * `poolnumber` - Number of threads used for hashing
///
/// # Behavior
///
/// Sends manifest version, command line, hash algorithm, signature algorithm,
/// optional header content, start time, thread count, and separator line.
#[allow(dead_code)]
pub fn write_headers(
    sign_tx: &std::sync::mpsc::Sender<SignMessage>,
    inputhash: &str,
    command_line: &str,
    header_file: &str,
    now: &chrono::DateTime<Utc>,
    poolnumber: usize,
) {
    send_sign_message("Manifest version|0.8.0\n".to_string(), 0, sign_tx);
    send_sign_message(format!("Command Line|{}\n", &command_line), 0, sign_tx);
    send_sign_message(format!("Hash SHA|{}\n", &inputhash), 0, sign_tx);
    send_sign_message("Signature algorithm|ED25519\n".to_string(), 0, sign_tx);

    let data = if header_file == "|||" {
        "No header file requested for inclusion.\n".to_string()
    } else {
        dump_header(header_file)
    };

    send_sign_message(data, 0, sign_tx);
    send_sign_message(format!("Start time was|{now}\n"), 0, sign_tx);
    send_sign_message(
        format!("Threads used for main hashing was|{poolnumber}\n"),
        0,
        sign_tx,
    );
    send_sign_message(format!("{SEPARATOR_LINE}\n"), 0, sign_tx);
}

/// Reads a manifest file line by line into a vector.
///
/// # Arguments
///
/// * `vec_of_lines` - Vector to populate with manifest lines
/// * `input_file` - Path to manifest file
/// * `fileoutput` - If true, shows progress spinner during read
///
/// # Panics
///
/// Panics if file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use signhash::read_manifest_file;
/// let mut lines = Vec::new();
/// read_manifest_file(&mut lines, "manifest.txt", true);
/// ```
#[allow(dead_code)]
pub fn read_manifest_file(vec_of_lines: &mut Vec<String>, input_file: &str, fileoutput: bool) {
    let f = match File::open(input_file) {
        Ok(f) => f,
        Err(why) => panic!(
            "Couldn't open manifest file for input at|{}|{}",
            input_file, why
        ),
    };
    let spinner = ProgressBar::new_spinner();
    let file = BufReader::new(&f);
    if fileoutput {
        spinner.set_prefix("Reading manifest:");
        spinner.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {elapsed_precise} {spinner:.yellow/cyan}")
                .expect("valid manifest read template"),
        );
    }
    for line in file.lines() {
        if fileoutput {
            spinner.tick();
        }
        vec_of_lines.push(line.unwrap());
    }
    if fileoutput {
        spinner.finish();
    }
}

/// Parses a manifest line into file name and structured metadata.
///
/// # Arguments
///
/// * `manifest_line` - Raw manifest line string
///
/// # Returns
///
/// Tuple of (`file_name`, `ManifestLine`) containing parsed fields.
///
/// # Format
///
/// Expected format: "type|path|bytes|time|hash|nonce|signature"
///
/// # Examples
///
/// ```no_run
/// use signhash::{parse_manifest_line, ManifestLine};
/// let line = "File|./test.txt|1024|01/01/2024 12:00:00|ABC123|NONCE|SIG";
/// let (path, manifest) = parse_manifest_line(line);
/// assert_eq!(path, "./test.txt");
/// ```
#[allow(dead_code)]
#[must_use]
pub fn parse_manifest_line(manifest_line: &str) -> (String, ManifestLine) {
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

/// Sends a manifest line message to the signing channel.
///
/// # Arguments
///
/// * `message_string` - Message text to send
/// * `len` - File length in bytes (0 for headers)
/// * `sign_tx` - Channel sender for transmitting messages
///
/// # Panics
///
/// Panics if channel send fails.
fn send_sign_message(
    message_string: impl Into<String>,
    len: u64,
    sign_tx: &std::sync::mpsc::Sender<SignMessage>,
) {
    let message = SignMessage {
        text: message_string.into(),
        file_len: len,
    };
    if let Err(why) = sign_tx.send(message) {
        panic!("Couldn't send to writing thread.|{}", why);
    }
}

/// Sends a check result message to the verification channel.
///
/// # Arguments
///
/// * `message_type` - Message type constant (`PRINT_MESSAGE`, `TICK_MESSAGE`, `END_MESSAGE`)
/// * `message_string` - Message text to send
/// * `verbose` - If true, message is only shown in verbose mode
/// * `check_tx` - Channel sender for transmitting check results
///
/// # Panics
///
/// Panics if channel send fails.
pub fn send_check_message(
    message_type: u8,
    message_string: impl Into<String>,
    verbose: bool,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    let message = CheckMessage {
        check_type: message_type,
        text: message_string.into(),
        verbose,
    };
    if let Err(why) = check_tx.send(message) {
        panic!("Couldn't send to writing thread.|{}\n", why);
    }
}

/// Sends either a pass or fail message based on a boolean condition.
///
/// # Arguments
///
/// * `pass_bool` - If true, sends pass message; otherwise sends fail message
/// * `pass_string` - Message to send on success (verbose=true)
/// * `fail_string` - Message to send on failure (verbose=false)
/// * `check_tx` - Channel sender for transmitting check results
///
/// # Examples
///
/// ```no_run
/// use signhash::{send_pass_fail_check_message, CheckMessage};
/// use std::sync::mpsc;
///
/// let (tx, rx) = mpsc::channel::<CheckMessage>();
/// let file_len = 1024u64;
/// let expected_len = 1024u64;
/// send_pass_fail_check_message(
///     file_len == expected_len,
///     "File size correct",
///     "File size mismatch",
///     &tx
/// );
/// ```
pub fn send_pass_fail_check_message(
    pass_bool: bool,
    pass_string: impl Into<String>,
    fail_string: impl Into<String>,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    if pass_bool {
        send_check_message(PRINT_MESSAGE, pass_string, true, check_tx);
    } else {
        send_check_message(PRINT_MESSAGE, fail_string, false, check_tx);
    }
}

// ============================================================================
// Helper functions for simplified CLI programs
// ============================================================================

use walkdir::WalkDir;

/// Collects all file paths from a directory recursively.
///
/// # Arguments
///
/// * `directory` - Root directory to walk
/// * `show_progress` - If true, displays a progress spinner during traversal
///
/// # Returns
///
/// Vector of file paths as strings, including the directory itself and all
/// subdirectories and files.
///
/// # Examples
///
/// ```no_run
/// use signhash::collect_files;
/// let files = collect_files("./src", true);
/// println!("Found {} files", files.len());
/// ```
///
/// # Panics
///
/// Panics if progress bar template is invalid.
#[must_use]
pub fn collect_files(directory: &str, show_progress: bool) -> Vec<String> {
    let spinner = ProgressBar::new_spinner();
    if show_progress {
        spinner.set_prefix("Constructing file list:");
        spinner.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {elapsed_precise} {spinner:.yellow/cyan}")
                .expect("valid spinner template"),
        );
    }

    let files: Vec<String> = WalkDir::new(directory)
        .into_iter()
        .map(|entry| {
            if show_progress {
                spinner.tick();
            }
            entry.unwrap().path().display().to_string()
        })
        .collect();

    if show_progress {
        spinner.finish();
    }
    files
}

/// Creates a configured progress bar with the specified styling.
///
/// # Arguments
///
/// * `len` - Total number of items to process
/// * `prefix` - Label to display before the progress bar
/// * `color` - Color name for the progress bar (e.g., "yellow", "green")
/// * `show` - If true, configures visible progress bar; if false, creates silent bar
///
/// # Returns
///
/// Configured `ProgressBar` instance.
///
/// # Examples
///
/// ```no_run
/// use signhash::create_progress_bar;
/// let bar = create_progress_bar(100, "Processing:", "green", true);
/// bar.inc(1);
/// bar.finish();
/// ```
///
/// # Panics
///
/// Panics if progress bar template is invalid.
#[must_use]
pub fn create_progress_bar(len: u64, prefix: &str, color: &str, show: bool) -> ProgressBar {
    let bar = ProgressBar::new(len);
    if show {
        bar.set_prefix(prefix.to_string());
        let template =
            format!("{{prefix}} {{wide_bar:.{color}/cyan}} {{pos}}/{{len}} {{elapsed_precise}}");
        bar.set_style(
            ProgressStyle::default_bar()
                .template(&template)
                .expect("valid progress template"),
        );
    }
    bar
}

/// Parses thread pool size from string, defaulting to CPU count if invalid.
///
/// # Arguments
///
/// * `input` - String containing thread count ("0" or invalid returns CPU count)
///
/// # Returns
///
/// Thread pool size to use. Returns CPU thread count if input is < 1,
/// determined using `std::thread::available_parallelism()` which respects
/// cgroups and CPU affinity settings.
///
/// # Panics
///
/// Panics if input cannot be parsed as usize.
///
/// # Examples
///
/// ```no_run
/// use signhash::get_pool_size;
/// let size = get_pool_size("4");  // returns 4
/// let auto = get_pool_size("0");  // returns CPU count
/// ```
pub fn get_pool_size(input: &str) -> usize {
    let size = input.parse::<usize>().unwrap_or_else(|why| {
        panic!("Please choose a number for the number of threads.|{}", why);
    });
    if size < 1 {
        std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
    } else {
        size
    }
}
