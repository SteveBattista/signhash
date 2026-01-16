mod hash_helper;
mod main_helper;

use hash_helper::HasherOptions;
use main_helper::{
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

        Self {
            public_key_file: matches
                .get_one::<String>("public")
                .map_or(DEFAULT_PUBIC_KEY_FILE_NAME.to_string(), Clone::clone),
            input_file: matches
                .get_one::<String>("input")
                .cloned()
                .unwrap_or_else(|| DEFAULT_MANIFEST_FILE_NAME.to_string()),
            output_file,
            fileoutput,
            poolnumber: get_pool_size(
                matches
                    .get_one::<String>("pool")
                    .map_or("0", String::as_str),
            ),
            input_directory: matches
                .get_one::<String>("directory")
                .map_or(PWD.to_string(), Clone::clone),
            verbose: matches.get_flag("verbose"),
            manifest_only: matches.get_flag("manifestonly"),
        }
    }
}

/// Parse manifest headers and return the hasher config, streaming hasher, byte count, and algorithm name.
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

/// Parse file entries from manifest, checking for duplicate nonces
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

/// Verify manifest footer (length, hash, signature)
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

/// Initialize environment: load public key, read manifest, and collect input files
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

/// Parse manifest headers and entries, returning parsed structures and hash context
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

/// Log initial execution information
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

/// Spawn writer thread responsible for emitting results
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

/// Execute parallel checks and return any remaining manifest entries
fn execute_parallel_checks(
    config: &Config,
    inputfiles: Vec<String>,
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
            check_line(path, hasher_option, manifest, public_key_bytes, check_tx, true);
        });
    } else {
        inputfiles.par_iter().for_each(|file| {
            let manifest_opt = manifest_map.lock().unwrap().remove(file);
            
            match manifest_opt {
                Some(manifest) => {
                    check_line(file, hasher_option, &manifest, public_key_bytes, check_tx, false);
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

/// Report missing files and verify manifest footer
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

    // Initialize key, manifest, and file list
    let (public_key_bytes, mut vec_of_lines, inputfiles) = initialize_data(&config);

    // Setup channel and configure rayon thread pool
    let (check_tx, check_rx) = mpsc::channel();
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.poolnumber)
        .build_global()
        .unwrap_or_else(|_| ());
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
        inputfiles,
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

    let _res = writer_child.join();
}
