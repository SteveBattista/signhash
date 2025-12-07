mod hash_helper;
mod main_helper;

use hash_helper::HasherOptions;
use main_helper::{
    check_line, collect_files, create_progress_bar, get_pool_size, parse_manifest_line,
    read_manifest_file, read_public_key, report_duplicative_and_insert_nonce, send_check_message,
    send_pass_fail_check_message, write_check_from_channel, CheckMessage, ManifestLine,
    BITS_IN_BYTES, DEFAULT_MANIFEST_FILE_NAME, DEFAULT_PUBIC_KEY_FILE_NAME, END_MESSAGE,
    NO_OUTPUTFILE, PRINT_MESSAGE, PUBLICKEY_LENGTH_IN_BYTES, PWD, SEPARATOR_LINE,
    SIGN_HEADER_MESSAGE_COUNT, SIGNED_LENGTH_IN_BYTES, TOKEN_SEPARATOR,
};

use data_encoding::HEXUPPER;
use scoped_threadpool::Pool;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::sync::mpsc;
use std::thread;

use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, Command};
use indicatif::ProgressBar;

const NUMBER_OF_LINES_UNTIL_FILE_LEN_MESSAGE: usize = 6;

fn build_cli() -> Command {
    Command::new("check_hash")
        .version("1.0.0")
        .author("Stephen Battista <stephen.battista@gmail.com>")
        .about("Verifies signed hash manifests for files")
        .arg(Arg::new("public")
            .short('u').long("public")
            .value_name("FILE")
            .help("Public key file location. Default: Signpub.txt"))
        .arg(Arg::new("input")
            .short('i').long("input")
            .value_name("FILE")
            .help("Manifest file location. Default: Manifest.txt"))
        .arg(Arg::new("output")
            .short('o').long("output")
            .value_name("FILE")
            .help("Output file location. Default: STDIO"))
        .arg(Arg::new("pool")
            .short('p').long("pool")
            .value_name("#")
            .help("Thread pool size. Default: CPU cores"))
        .arg(Arg::new("directory")
            .short('d').long("directory")
            .value_name("DIRECTORY")
            .help("Directory to check. Default: current directory"))
        .arg(Arg::new("verbose")
            .short('v').long("verbose")
            .help("Print matches as well as failures")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("manifestonly")
            .short('m').long("manifestonly")
            .help("Check manifest validity only, ignore -d option")
            .action(ArgAction::SetTrue))
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
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let output_file = matches.get_one::<String>("output").cloned()
            .unwrap_or_else(|| NO_OUTPUTFILE.to_string());
        let fileoutput = output_file != NO_OUTPUTFILE;
        
        Self {
            public_key_file: matches.get_one::<String>("public")
                .map_or(DEFAULT_PUBIC_KEY_FILE_NAME.to_string(), Clone::clone),
            input_file: matches.get_one::<String>("input").cloned()
                .unwrap_or_else(|| DEFAULT_MANIFEST_FILE_NAME.to_string()),
            output_file,
            fileoutput,
            poolnumber: get_pool_size(matches.get_one::<String>("pool").map_or("0", String::as_str)),
            input_directory: matches.get_one::<String>("directory")
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
    let inc = || if fileoutput { nonce_bar.inc(1); };
    
    // Parse header lines
    let mut version_line = vec_of_lines.remove(0); inc();
    let mut command_line = vec_of_lines.remove(0); inc();
    let mut hash_line = vec_of_lines.remove(0); inc();
    
    // Extract hash algorithm
    let hash_algo = hash_line.split(TOKEN_SEPARATOR).nth(1).unwrap_or("256").to_string();
    let hasher_option = HasherOptions::new(&hash_algo);
    
    // Initialize streaming hasher with header lines
    version_line += "\n";
    let mut hasher = hasher_option.clone().multi_hash_update(version_line.as_bytes());
    let mut file_len = version_line.len();

    command_line += "\n";
    hasher = hasher.multi_hash_update(command_line.as_bytes());
    file_len += command_line.len();

    hash_line += "\n";
    hasher = hasher.multi_hash_update(hash_line.as_bytes());
    file_len += hash_line.len();

    // Process remaining header lines until separator
    loop {
        let mut line = vec_of_lines.remove(0); inc();
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
) -> (HashMap<String, ManifestLine>, hash_helper::StreamingHasher, usize) {
    let mut manifest_map = HashMap::new();
    let mut nonces: HashMap<String, String> = HashMap::new();
    let mut hasher = hasher;
    let mut file_len = file_len;

    // Process separator line
    let mut line = vec_of_lines.remove(0);
    line += "\n";
    hasher = hasher.multi_hash_update(line.as_bytes());
    file_len += line.len();
    if fileoutput { nonce_bar.inc(1); }

    // Process file entries
    loop {
        let mut line = vec_of_lines.remove(0);
        if line == SEPARATOR_LINE {
            // Put separator back - we'll need it later
            vec_of_lines.insert(0, line);
            break;
        }
        
        let (file_name, manifest_struct) = parse_manifest_line(&line);
        report_duplicative_and_insert_nonce(&mut nonces, &manifest_struct.nonce, &file_name, check_tx);
        manifest_map.insert(file_name, manifest_struct);
        
        line += "\n";
        hasher = hasher.multi_hash_update(line.as_bytes());
        file_len += line.len();
        if fileoutput { nonce_bar.inc(1); }
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
        format!("Failure|manifest hash|{}|observed|{digest_text}\n", tokens[1]),
        check_tx,
    );

    // Verify signature
    let line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = line.split(TOKEN_SEPARATOR).collect();
    
    let signature_bytes = HEXUPPER.decode(tokens[1].as_bytes()).unwrap_or_else(|why| {
        send_check_message(PRINT_MESSAGE, 
            format!("Failure|couldn't decode hex signature|{why}\n"), false, check_tx);
        vec![0u8; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES]
    });

    let mut sig_array = [0u8; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES];
    sig_array.copy_from_slice(&signature_bytes);

    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
    match public_key.verify(digest_text.as_bytes(), &sig_array) {
        Ok(()) => send_check_message(PRINT_MESSAGE, 
            "Correct|manifest signature verified.\n", false, check_tx),
        Err(_) => send_check_message(PRINT_MESSAGE,
            "Failure|manifest signature verification failed.\n", false, check_tx),
    }
}

fn main() {
    let now: DateTime<Utc> = Utc::now();
    let args: Vec<String> = env::args().collect();
    let config = Config::from_matches(&build_cli().get_matches());

    // Load public key
    let mut public_key_bytes = [0u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];
    read_public_key(&config.public_key_file, &mut public_key_bytes);

    // Read manifest
    let mut vec_of_lines: Vec<String> = Vec::new();
    read_manifest_file(&mut vec_of_lines, &config.input_file, config.fileoutput);

    // Collect files (empty if manifest-only)
    let inputfiles = if config.manifest_only {
        Vec::new()
    } else {
        collect_files(&config.input_directory, config.fileoutput)
    };

    // Setup
    let (check_tx, check_rx) = mpsc::channel();
    let mut pool = Pool::new(config.poolnumber.try_into().unwrap());
    let bar_len = vec_of_lines.len().saturating_sub(SIGN_HEADER_MESSAGE_COUNT + 10) as u64;
    let nonce_bar = create_progress_bar(bar_len, "Parsing manifest:", "green", config.fileoutput);

    // Parse manifest headers
    let (hasher_option, hasher, file_len, hash_algo) = 
        parse_manifest_headers(&mut vec_of_lines, config.fileoutput, &nonce_bar);

    // Log check info
    send_check_message(PRINT_MESSAGE, format!("Command Line|{}\n", args.join(" ")), true, &check_tx);
    send_check_message(PRINT_MESSAGE, format!("Start time|{now}\n"), true, &check_tx);
    send_check_message(PRINT_MESSAGE, format!("Threads|{}\n", config.poolnumber), true, &check_tx);
    send_check_message(PRINT_MESSAGE, format!("Hash algorithm|{hash_algo}\n"), true, &check_tx);
    send_check_message(PRINT_MESSAGE, "Signature|ED25519\n", true, &check_tx);

    // Parse file entries
    let (mut manifest_map, hasher, file_len) = parse_manifest_entries(
        &mut vec_of_lines, hasher, file_len,
        config.fileoutput, &nonce_bar, &check_tx
    );
    if config.fileoutput { nonce_bar.finish(); }

    // Setup verification progress bar and writer thread
    let check_prefix = if config.manifest_only { "Checking signatures:" } else { "Checking files:" };
    let progress_bar = create_progress_bar(bar_len, check_prefix, "yellow", config.fileoutput);
    
    let (verbose, output_file, fileoutput) = (config.verbose, config.output_file.clone(), config.fileoutput);
    let writer_child = thread::spawn(move || {
        write_check_from_channel(verbose, &check_rx, &output_file, fileoutput, &progress_bar);
    });

    // Parallel file checking
    pool.scoped(|scoped| {
        if config.manifest_only {
            for (path, manifest) in manifest_map.drain() {
                let tx = check_tx.clone();
                let h = hasher_option.clone();
                scoped.execute(move || {
                    check_line(&path, &h, &manifest, &public_key_bytes, &tx, true);
                });
            }
        } else {
            for file in inputfiles {
                match manifest_map.remove(&file) {
                    Some(manifest) => {
                        let tx = check_tx.clone();
                        let h = hasher_option.clone();
                        scoped.execute(move || {
                            check_line(&file, &h, &manifest, &public_key_bytes, &tx, false);
                        });
                    }
                    None => send_check_message(PRINT_MESSAGE,
                        format!("Failure|{file}|not in manifest\n"), false, &check_tx),
                }
            }
        }
    });

    // Report missing files
    for (path, _) in manifest_map.drain() {
        send_check_message(PRINT_MESSAGE,
            format!("Failure|{path}|in manifest but not found\n"), false, &check_tx);
    }

    // Verify footer and end
    verify_manifest_footer(&mut vec_of_lines, hasher, file_len, &public_key_bytes, &check_tx);
    send_check_message(END_MESSAGE, "End", false, &check_tx);
    let _res = writer_child.join();
}
