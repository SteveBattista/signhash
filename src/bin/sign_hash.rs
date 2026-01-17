mod hash_helper;
mod main_helper;

use hash_helper::HasherOptions;
use main_helper::{
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
}

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

    // Validate input directory exists
    if !std::path::Path::new(input_directory).exists() {
        eprintln!("Error: Directory '{input_directory}' does not exist");
        std::process::exit(1);
    }
    if !std::path::Path::new(input_directory).is_dir() {
        eprintln!("Error: '{input_directory}' is not a directory");
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
