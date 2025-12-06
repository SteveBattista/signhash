mod hash_helper;
mod main_helper;

use crate::main_helper::create_keys;
use crate::main_helper::create_line;
use crate::main_helper::provide_unique_nonce;
use crate::main_helper::write_headers;
use crate::main_helper::write_key;
use crate::main_helper::write_manifest_from_channel;
use crate::main_helper::WriterContext;
use crate::main_helper::SignMessage;
use crate::main_helper::BITS_IN_BYTES;
use crate::main_helper::DEFAULT_PUBIC_KEY_FILE_NAME;
use crate::main_helper::NONCE_LENGTH_IN_BYTES;
use crate::main_helper::NO_OUTPUTFILE;
use crate::main_helper::PRIVATEKEY_LENGTH_IN_BYTES;
use crate::main_helper::PUBIC_KEY_STRING_ED25519;
use crate::main_helper::PUBLICKEY_LENGTH_IN_BYTES;
use crate::main_helper::PWD;
use crate::main_helper::SIGN_HEADER_MESSAGE_COUNT;

use crate::hash_helper::HasherOptions;

use scoped_threadpool::Pool;
use std::convert::TryInto;

use std::thread;

use chrono::{DateTime, Utc};
use clap::{Arg, Command};

//use ring::digest::{Algorithm, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};

use std::collections::HashMap;
use std::env;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use std::io::stdout;
use std::io::Write;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

use walkdir::WalkDir;

#[allow(clippy::too_many_lines)]
fn main() {
    let now: DateTime<Utc> = Utc::now();
    let start = Instant::now();
    let args: Vec<String> = env::args().collect();
    let matches = Command::new("sign_hash")
        .version("1.0.0")
        .author("Stephen Battista <stephen.battista@gmail.com>")
        .about("Implements a signed hash for files")
        .arg(
            Arg::new("hash")
                .short('a')
                .long("hash")
                .value_name("128| 256 | 384 | 512 | 512_256 | blake3")
                .help("Chooses what hash algorithm to use SHA1 -> (128), SHA256->(256), SHA384->(384), SHA512->(512), SHA512_256->(512_256) or blake3->(blake3). Default is SHA256. SHA512 for files is faster than SHA256 by about 30%. Please don't use SHA1 unless you are using it to line up with threat intelligence.")
                .num_args(1),
        )
        .arg(
            Arg::new("signing")
                .short('s')
                .long("signing")
                .value_name("ED25519")
                .help("Chooses what signing algorithm to use ED25519. Default is ED25519. Will implement post quantum signature at some point.")
                .num_args(1),
        )
        .arg(
            Arg::new("public")
                .short('u')
                .long("public")
                .value_name("FILE")
                .help("This option allows for the user to set the location of the public key. If not used, Signpub.key is default.")
                .num_args(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("This option allows for the user to set the location of the manifest file.  If not used, STDIO is default.")
                .num_args(1),
        )
        .arg(
            Arg::new("pool")
                .short('p')
                .long("pool")
                .value_name("#")
                .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is number of CPU cores. Negative numbers set pool to default. This does not include additional threads generated when using blake3. Warning: Large numbers (> 60) may cause the program not to hash all files.")
                .num_args(1),
        )
        .arg(
            Arg::new("include")
                .short('i')
                .long("include")
                .value_name("FILE")
                .help("Name of file that you would like to include in the header.")
                .num_args(1),
        )
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIRECTORY")
                .help("Directory to start hashing. Default is current working directory. Program does not follow symbolic links.")
                .num_args(1),
        )
        .get_matches();

    let inputhash = matches
        .get_one::<String>("hash")
        .map_or("256", std::string::String::as_str);
    let hasher_option = HasherOptions::new(inputhash);

    let signing = matches
        .get_one::<String>("signing")
        .map_or("ED25519", std::string::String::as_str);
    match signing {
        "ED25519" => (),
        _ => {
            panic!("Please choose ED25519 for type of signature algorithm.");
        }
    }

    let manifest_file = matches
        .get_one::<String>("output")
        .cloned()
        .unwrap_or_else(|| NO_OUTPUTFILE.to_string());
    let fileoutput = manifest_file != NO_OUTPUTFILE;
    let public_key_file = matches
        .get_one::<String>("public")
        .map_or(DEFAULT_PUBIC_KEY_FILE_NAME, std::string::String::as_str);

    let inputpool = matches
        .get_one::<String>("pool")
        .map_or("0", std::string::String::as_str);
    let mut poolnumber = inputpool.parse::<usize>().unwrap_or_else(|why| {
        panic!("Please choose a number for the number of threads.|{}", why);
    });
    if poolnumber < 1 {
        poolnumber = num_cpus::get();
    }

    let mut pool = Pool::new(poolnumber.try_into().unwrap());

    let (sign_tx, sign_rx): (Sender<SignMessage>, Receiver<SignMessage>) = mpsc::channel();

    let header_file = matches
        .get_one::<String>("include")
        .map_or("|||", std::string::String::as_str);

    let input_directoy = matches
        .get_one::<String>("directory")
        .map_or(PWD, std::string::String::as_str);

    let mut inputfiles: Vec<String> = Vec::new();
    let spinner = ProgressBar::new_spinner();
    if fileoutput {
        spinner.set_prefix("Constructing file list:");
        spinner.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {elapsed_precise} {spinner:.yellow/cyan}")
                .expect("valid spinner template"),
        );
    }
    for entry in WalkDir::new(input_directoy) {
        inputfiles.push(entry.unwrap().path().display().to_string());
        if fileoutput {
            spinner.tick();
        }
    }
    if fileoutput {
        spinner.finish();
    }

    let mut private_key_bytes: [u8; PRIVATEKEY_LENGTH_IN_BYTES / BITS_IN_BYTES] =
        [0; PRIVATEKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];
    let mut public_key_bytes: [u8; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES] =
        [0; PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES];

    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    write_key(&public_key_bytes, public_key_file, PUBIC_KEY_STRING_ED25519);

    let mut nonce_bytes: [u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES] =
        [0; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES];

    let mut nonces: HashMap<[u8; NONCE_LENGTH_IN_BYTES / BITS_IN_BYTES], i32> = HashMap::new();

    write_headers(
        &sign_tx,
        inputhash,
        &args.join(" "),
        header_file,
        &now,
        poolnumber,
    );

    let progress_bar = ProgressBar::new(inputfiles.len().try_into().unwrap());
    if fileoutput {
        progress_bar.set_prefix("Hashing files :");
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {wide_bar:.yellow/cyan} {pos}/{len} {elapsed_precise}")
                .expect("valid hash progress template"),
        );
    }
    let num_files = inputfiles.len();
    let thread_hasher_option = hasher_option.clone();
    let writer_child = thread::Builder::new()
        .name("Writer".to_string())
        .spawn(move || {
            let ctx = WriterContext {
                manifest_file: &manifest_file,
                progress_bar: &progress_bar,
                file_output: fileoutput,
            };
            write_manifest_from_channel(
                num_files + SIGN_HEADER_MESSAGE_COUNT,
                thread_hasher_option,
                &private_key_bytes,
                &sign_rx,
                start,
                ctx,
            );
        })
        .unwrap();

    pool.scoped(|scoped| {
        stdout().flush().unwrap();
        for file in inputfiles {
            let thread_tx = sign_tx.clone();
            let thread_hasher_option = hasher_option.clone();
            provide_unique_nonce(&mut nonce_bytes, &mut nonces, rand::rng());
            scoped.execute(move || {
                create_line(
                    file.clone(),
                    &thread_hasher_option,
                    &nonce_bytes,
                    &private_key_bytes,
                    &thread_tx,
                );
            });
        }
    });
    let _res = writer_child.join();
}
