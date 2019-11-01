#![forbid(unsafe_code)]

use signhash::SIGN_HEADER_MESSAGE_COUNT;
use signhash::check_line;
use signhash::get_next_manifest_line;
use signhash::parse_hash_manifest_line;
use signhash::parse_next_manifest_line;
use signhash::read_manifest_file;
use signhash::read_public_key;
use signhash::report_duplicatve_and_insert_nonce;
use signhash::send_check_message;
use signhash::send_pass_fail_check_message;
use signhash::write_check_from_channel;
use signhash::CheckMessage;
use signhash::ManifestLine;
use signhash::BITS_IN_BYTES;
use signhash::DEFAULT_MANIFEST_FILE_NAME;
use signhash::DEFAULT_PUBIC_KEY_FILE_NAME;
use signhash::END_MESSAGE;
use signhash::PRINT_MESSAGE;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::PWD;
use signhash::SEPARATOR_LINE;
use signhash::SIGNED_LENGTH_IN_BYTES;
use signhash::TOKEN_SEPARATOR;

use scoped_threadpool::Pool;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::error::Error;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use data_encoding::HEXUPPER;

use clap::{App, Arg};

use ring::digest::Context;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

use walkdir::WalkDir;

use chrono::DateTime;
use chrono::Utc;

const NUMBRER_OF_LINES_UNTIL_FILE_LEN_MESSAGE: usize = 7;
const NO_OUTPUTFILE: &str = "|||";

fn main() {
    let now: DateTime<Utc> = Utc::now();
    let args: Vec<String> = env::args().collect();
    let matches = App::new("check_hash")
    .version("0.1.0")
    .author("Stephen Battista <stephen.battista@gmail.com>")
    .about("Implements a signed hash for files")
    .arg(Arg::with_name("public")
        .short("u")
        .long("public")
        .value_name("FILE")
        .help("This option allows for the user to set the location of the public key. If not used, Signpub.key is default.")
        .takes_value(true))
    .arg(Arg::with_name("input")
        .short("i")
        .long("input")
        .value_name("FILE")
        .help("This option allows for the user to set the location of the manifest file.  If not used, Manifest.txt is default. ")
        .takes_value(true))
    .arg(Arg::with_name("output")
        .short("o")
        .long("output")
        .value_name("FILE")
        .help("This option allows for the user to set the location of the output file.  If not used, STDIO is default. ")
        .takes_value(true))
    .arg(Arg::with_name("pool")
        .short("p")
        .long("pool")
        .value_name("#")
        .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is number of CPU cores. Negative numbers set pool to default. Warning: Large numbers (> 60) may cause the program not to hash all files.")
        .takes_value(true))
    .arg(Arg::with_name("directory")
        .short("d")
        .long("directory")
        .value_name("DIRECTORY")
        .help("Directory to start hashing. Default is current working directory. Program does not follow symbolic links.")
        .takes_value(true))
    .arg(Arg::with_name("verbose")
         .short("v")
        .long("verbose")
        .help("Use -v flag to also print out when things match."))
    .arg(Arg::with_name("manifestonly")
        .short("m")
        .long("manifestonly")
        .help("Use -m flag to check the validity of the manifest only. Will ignore -d option."))
    .get_matches();

    let mut public_key_bytes: [u8; (PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES)] =
        [0; (PUBLICKEY_LENGTH_IN_BYTES / BITS_IN_BYTES)];
    let public_key_file = matches
        .value_of("public")
        .unwrap_or(DEFAULT_PUBIC_KEY_FILE_NAME);
    read_public_key(public_key_file, &mut public_key_bytes);

    let output_file = matches
        .value_of("output")
        .unwrap_or(NO_OUTPUTFILE)
        .to_string();
    let fileoutput = output_file != NO_OUTPUTFILE;

    let input_file = matches
        .value_of("input")
        .unwrap_or(DEFAULT_MANIFEST_FILE_NAME)
        .to_string();

    let mut vec_of_lines: Vec<String> = Vec::new();
    read_manifest_file(&mut vec_of_lines, &input_file, fileoutput);

    let inputpool = matches.value_of("pool").unwrap_or("0");
    let poolresult = inputpool.parse();
    let mut poolnumber;
    match poolresult {
        Ok(n) => poolnumber = n,
        Err(_e) => {
            panic!("Please choose a number for the number of threads.");
        }
    }
    if poolnumber < 1 {
        poolnumber = num_cpus::get();
    }

    let mut pool = Pool::new(poolnumber.try_into().unwrap());
    let (check_tx, check_rx): (Sender<CheckMessage>, Receiver<CheckMessage>) = mpsc::channel();

    let input_directoy = matches.value_of("directory").unwrap_or(PWD);

    let verbose: bool = matches.is_present("verbose");

    let manifest_only = matches.is_present("manifestonly");

    let mut inputfiles: Vec<String> = Vec::new();
    if !manifest_only {
        let spinner = ProgressBar::new_spinner();
        if fileoutput {
            spinner.set_prefix("Constucting file list:");
            spinner.set_style(
                ProgressStyle::default_bar().template("{prefix} {elapsed_precise} {spinner:.yellow/cyan}"),
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

    }
    let nonce_bar = ProgressBar::new((vec_of_lines.len()-(SIGN_HEADER_MESSAGE_COUNT +10)).try_into().unwrap()); // the 2 is for the seperators
    if fileoutput {
        nonce_bar.set_prefix("Parsing and checking for duplicate nonces:");
        nonce_bar.set_style(
            ProgressStyle::default_bar().template("{prefix} {wide_bar:.green/cyan} {pos}/{len} {elapsed_precise}"),
        );
    }
    let progress_bar = ProgressBar::new((vec_of_lines.len()-(SIGN_HEADER_MESSAGE_COUNT + 10 )).try_into().unwrap()); // the 2 is for the seperators

    let mut version_line = vec_of_lines.remove(0);
    if fileoutput{
        nonce_bar.inc(1);
    }
    let mut command_line = vec_of_lines.remove(0);
    if fileoutput{
        nonce_bar.inc(1);
    }
    let mut hash_line = vec_of_lines.remove(0);
    if fileoutput{
        nonce_bar.inc(1);
    }
    let hashalgo = parse_hash_manifest_line(hash_line.clone());

    let mut file_hash_context = Context::new(hashalgo);

    let mut file_len: usize = 0;

    version_line += "\n";
    file_hash_context.update(version_line.as_bytes());
    file_len += version_line.len();

    command_line += "\n";
    file_hash_context.update(command_line.as_bytes());
    file_len += command_line.len();

    hash_line += "\n";
    file_hash_context.update(hash_line.as_bytes());
    file_len += hash_line.len();

    let mut manifest_line = vec_of_lines.remove(0);

    while manifest_line != SEPARATOR_LINE {
        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
        if fileoutput {
         nonce_bar.inc(1);
        }
    }


    send_check_message(
        PRINT_MESSAGE,
        format!("Command Line|{}\n", args.join(" ")),
        true,
        &check_tx,
    );
    send_check_message(
        PRINT_MESSAGE,
        format!("Start time was|{}\n", now.to_string()),
        true,
        &check_tx,
    );
    send_check_message(
        PRINT_MESSAGE,
        format!("Threads used for main hashing was|{}\n", poolnumber),
        true,
        &check_tx,
    );

    let tokens: Vec<&str> = hash_line.split(TOKEN_SEPARATOR).collect();
    send_check_message(
        PRINT_MESSAGE,
        format!("Hash used|{}", tokens[1]).to_string(),
        true,
        &check_tx,
    );
    send_check_message(
        PRINT_MESSAGE,
        "Signature algorithm|ED25519\n".to_string(),
        true,
        &check_tx,
    );

    let mut type_of_line = String::new();
    let mut file_name_line = String::new();
    let mut bytes_line = String::new();
    let mut time_line = String::new();
    let mut nonce_line = String::new();
    let mut hash_line = String::new();
    let mut sign_line = String::new();
    manifest_line = get_next_manifest_line(
        manifest_line,
        &mut vec_of_lines,
        &mut file_hash_context,
        &mut file_len,
    );
    if fileoutput{
        nonce_bar.inc(1);
    }
    let nonces: &mut HashMap<String, String> = &mut HashMap::new();
    let manifest_map: &mut HashMap<String, ManifestLine> = &mut HashMap::new();
    while manifest_line != SEPARATOR_LINE {
        parse_next_manifest_line(
            &manifest_line,
            &mut type_of_line,
            &mut file_name_line,
            &mut bytes_line,
            &mut time_line,
            &mut hash_line,
            &mut nonce_line,
            &mut sign_line,
        );

        report_duplicatve_and_insert_nonce(
            nonces,
            nonce_line.clone(),
            file_name_line.clone(),
            &check_tx,
        );

        let manifist_struct = ManifestLine {
            file_type: type_of_line.clone(),
            bytes: bytes_line.clone(),
            time: time_line.clone(),
            hash: hash_line.clone(),
            nonce: nonce_line.clone(),
            sign: sign_line.clone(),
        };
        manifest_map.insert(file_name_line.clone(), manifist_struct);

        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
        if fileoutput {
            nonce_bar.inc(1);
        }
    }

    if fileoutput {
        nonce_bar.finish();
    }

    if fileoutput {
        if manifest_only{
            progress_bar.set_prefix("Checking signatures :");
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix} {wide_bar:.green/cyan} {pos}/{len} {elapsed_precise}"),
            );
        } else{
            progress_bar.set_prefix("Checking files and signatures :");
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix} {wide_bar:.yellow/cyan} {pos}/{len} {elapsed_precise}"),
            );
        }

    }

    let writer_child = thread::Builder::new()
        .name("Writer".to_string())
        .spawn(move || {
            write_check_from_channel(verbose, check_rx, output_file, fileoutput, progress_bar);
        })
        .unwrap();

    pool.scoped(|scoped| {
        if manifest_only {
            while !(manifest_map.is_empty()) {
                for (file_line, manifest_structure) in manifest_map.drain() {
                    let thread_tx = check_tx.clone();
                    scoped.execute(move || {
                        check_line(
                            file_line,
                            hashalgo,
                            manifest_structure,
                            &public_key_bytes,
                            thread_tx,
                            true
                        );
                    });
                }
            }
        } else {
        for file in inputfiles {
            match manifest_map.remove(&file) {
                Some(file_line) => {
                    let thread_tx = check_tx.clone();
                    scoped.execute(move || {
                        check_line(
                            file,
                            hashalgo,
                            file_line,
                            &public_key_bytes,
                            thread_tx,
                            false
                        );
                    });
                }
                None => {
                    send_check_message(
                        PRINT_MESSAGE,
                        format!(
                            "Failure|{}|was in the directory search but not found in directory manifest.\n",
                            file,
                        )
                        .to_string(),
                        false,
                        &check_tx,
                    );
                }
            };
        }
    }
});

    if !(manifest_map.is_empty()) {
        for (file_line, _manifest_structure) in manifest_map.drain(){
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "Failure|{}|was in the manifest but not found in directory search.\n",
                    file_line
                )
                .to_string(),
                false,
                &check_tx,
            );
        }
    }

    for _x in 0..NUMBRER_OF_LINES_UNTIL_FILE_LEN_MESSAGE {
        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
    }

    manifest_line += "\n";
    file_hash_context.update(manifest_line.as_bytes());

    let tokens: Vec<&str> = manifest_line.split(TOKEN_SEPARATOR).collect();
    send_pass_fail_check_message(
        tokens[1][..tokens[1].len() - 1] == format!("{}", file_len),
        format!("Correct| file length is|{}\n", file_len),
        format!(
            "Failure|manifest length|{}|observed length|{}\n",
            &tokens[1][..tokens[1].len() - 1],
            file_len
        ),
        &check_tx,
    );

    let digest = file_hash_context.finish();
    let digest_text = HEXUPPER.encode(&digest.as_ref());
    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split(TOKEN_SEPARATOR).collect();
    send_pass_fail_check_message(
        tokens[1] == digest_text,
        format!("Correct|file hash is|{}\n", digest_text),
        format!(
            "Failure|manifest hash|{}|observed hash|{}\n",
            tokens[1], digest_text
        ),
        &check_tx,
    );

    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split(TOKEN_SEPARATOR).collect();

    let local_key = match HEXUPPER.decode(tokens[1].as_bytes()) {
        Ok(local_key) => (local_key),
        Err(why) => {
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "Failure|couldn't decode hex signature for manifest file|{}.\n",
                    why.description()
                ),
                false,
                &check_tx,
            );
            vec![0; SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES]
        }
    };
    // figure this out don't dont want to crash
    let mut signature_key_bytes: [u8; (SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES)] =
        [0; (SIGNED_LENGTH_IN_BYTES / BITS_IN_BYTES)];

    signature_key_bytes[..].clone_from_slice(&local_key[..]);

    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
    match public_key.verify(digest_text.as_bytes(), &signature_key_bytes[..]) {
        Ok(_x) => {
            send_check_message(
                PRINT_MESSAGE,
                "Correct|signature of manifest is correct.\n".to_string(),
                false, // This guarantees a response so that someone can't trick the system by includng the END_OF_MESSAGES earlier in the file.
                &check_tx,
            );
        }
        Err(_) => {
            send_check_message(
                PRINT_MESSAGE,
                "Failure|signature of manifest did not match the hash in the manifest.\n"
                    .to_string(),
                false,
                &check_tx,
            );
        }
    };
    send_check_message(END_MESSAGE, "End".to_string(), false, &check_tx);

    let _res = writer_child.join();
}
