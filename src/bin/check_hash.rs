#![forbid(unsafe_code)]
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
use signhash::DEFAULT_MANIFEST_FILE_NAME;
use signhash::DEFAULT_PUBIC_KEY_FILE_NAME;
use signhash::END_OF_MESSAGES;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::SEPERATOR;
use signhash::SIGNED_LENGH_IN_BYTES;

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
const NO_OUTPUTFILE: &'static str = "|||";

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
        .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is number of CPU cores. Negative numbers set pool to default. Warning: Large numbers (> 60) may cause the progam not to hash all files.")
        .takes_value(true))
    .arg(Arg::with_name("directory")
        .short("d")
        .long("directory")
        .value_name("DIRECTORY")
        .help("Directory to start hashing. Default is current working directory.Those that can not be found will be ommited from the results. Directories will be ommitted. Links will be treated like normal files.")
        .takes_value(true))
    .arg(Arg::with_name("v")
         .short("v")
        .long("verbose")
        .help("Use -v flag to also print out when things match."))
    .get_matches();

    let mut public_key_bytes: [u8; (PUBLICKEY_LENGTH_IN_BYTES / 8)] =
        [0; (PUBLICKEY_LENGTH_IN_BYTES / 8)];
    let public_key_file = matches
        .value_of("public")
        .unwrap_or(DEFAULT_PUBIC_KEY_FILE_NAME);
    read_public_key(public_key_file, &mut public_key_bytes);

    let output_file = matches
        .value_of("output")
        .unwrap_or(NO_OUTPUTFILE)
        .to_string();

    let mut fileoutput = true;
    if output_file == NO_OUTPUTFILE {
        fileoutput = false;
    }

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

    let input_directoy = matches.value_of("directory").unwrap_or(".");

    let verbose: bool;
    verbose = matches.is_present("v");

    let mut inputfiles: Vec<String> = Vec::new();
    let spinner = ProgressBar::new_spinner();
    if fileoutput {
        spinner.set_prefix("Constucting file list took:");
        spinner.set_style(
            ProgressStyle::default_bar().template("{prefix} {elapsed_precise} {spinner}"),
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

    let mut version_line = vec_of_lines.remove(0);
    let mut command_line = vec_of_lines.remove(0);
    let mut hash_line = vec_of_lines.remove(0);

    let hashalgo = parse_hash_manifest_line(hash_line.clone());

    let mut file_hash_context = Context::new(hashalgo);

    let mut file_len: usize = 0;

    version_line = version_line + "\n";
    file_hash_context.update(version_line.as_bytes());
    file_len = file_len + version_line.len();

    command_line = command_line + "\n";
    file_hash_context.update(command_line.as_bytes());
    file_len = file_len + command_line.len();

    hash_line = hash_line + "\n";
    file_hash_context.update(hash_line.as_bytes());
    file_len = file_len + hash_line.len();

    let mut manifest_line = vec_of_lines.remove(0);

    while manifest_line != SEPERATOR {
        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
    }

    let bar = ProgressBar::new(inputfiles.len().try_into().unwrap());
    if fileoutput {
        bar.set_prefix("Number of Files Checked:");
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {wide_bar} {pos}/{len} {elapsed_precise}"),
        );
    }

    let writer_child = thread::Builder::new()
        .name("Writer".to_string())
        .spawn(move || {
            write_check_from_channel(verbose, check_rx, output_file, fileoutput);
        })
        .unwrap();

    send_check_message(
        format!("Command Line|{}\n", args.join(" ")),
        true,
        &check_tx,
    );
    send_check_message(
        format!("Start time was|{}\n", now.to_string()),
        true,
        &check_tx,
    );
    send_check_message(
        format!("Threads used for main hashing was|{}\n", poolnumber),
        true,
        &check_tx,
    );

    let tokens: Vec<&str> = hash_line.split('|').collect();
    send_check_message(
        format!("Hash used|{}", tokens[1]).to_string(),
        true,
        &check_tx,
    );
    send_check_message(
        format!("Signature algorthim|ED25519\n").to_string(),
        true,
        &check_tx,
    );

    let nonces: &mut HashMap<String, String> = &mut HashMap::new();
    let manifest_map: &mut HashMap<String, ManifestLine> = &mut HashMap::new();

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

    while manifest_line != SEPERATOR {
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
            check_tx.clone(),
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
    }

    pool.scoped(|scoped| {
        for file in inputfiles {
            match manifest_map.remove(&file) {
                Some(file_line) => {
                    let thread_tx = check_tx.clone();
                    scoped.execute(move || {
                        let _x =
                            check_line(file, hashalgo, file_line, &public_key_bytes, thread_tx);
                    });
                    if fileoutput {
                        bar.inc(1); //For some reason the bar stalls
                    }
                }
                None => {
                    send_check_message(
                        format!(
                            "{}|was in the directory search but not found in direcorty manifest.\n",
                            file,
                        )
                        .to_string(),
                        false,
                        &check_tx,
                    );
                }
            };
        }
    });
    bar.finish();
    if manifest_map.len() > 0 {
        for (file_line, _manifest_structure) in manifest_map.drain().take(1) {
            send_check_message(
                format!(
                    "{}|was in the manifest but not found in direcorty search.\n",
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

    let mut manifest_line2 = manifest_line.clone();

    manifest_line2 = manifest_line2 + "\n";
    file_hash_context.update(manifest_line2.as_bytes());

    let tokens: Vec<&str> = manifest_line.split('|').collect();
    send_pass_fail_check_message(
        tokens[1] == format!("{}", file_len),
        "File lengh of manifest is corect.\n".to_string(),
        format!(
            "File lengh was reported in manifest as|{}. Observed length of manifest is|{}. \n",
            tokens[1], file_len
        ),
        &check_tx,
    );

    let digest = file_hash_context.finish();
    let digest_text = HEXUPPER.encode(&digest.as_ref());
    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split('|').collect();
    send_pass_fail_check_message(
        tokens[1] == digest_text,
        "Manifest digest is correct.\n".to_string(),
        format!(
            "Hash was reported as|{}|in manifest. Observed hash is|{}.\n",
            tokens[1], digest_text
        ),
        &check_tx,
    );

    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split('|').collect();

    let local_key = match HEXUPPER.decode(tokens[1].as_bytes()) {
        Ok(local_key) => (local_key),
        Err(why) => {
            send_check_message(
                format!(
                    "Couldn't decode hex signature for manifest file|{}.\n",
                    why.description()
                ),
                false,
                &check_tx,
            );
            vec![0; SIGNED_LENGH_IN_BYTES / 8]
        }
    };
    // figure this out don't dont want to crash
    let mut signature_key_bytes: [u8; (SIGNED_LENGH_IN_BYTES / 8)] =
        [0; (SIGNED_LENGH_IN_BYTES / 8)];

    for x in 0..SIGNED_LENGH_IN_BYTES / 8 {
        signature_key_bytes[x] = local_key[x];
    }
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
    match public_key.verify(digest_text.as_bytes(), &signature_key_bytes[..]) {
        Ok(_x) => {
            send_check_message(
                format!("Signature of manifest is correct.\n",).to_string(),
                false, // This garuntees a response so that someone can't trick the system by includng the END_OF_MESSAGES eariler in the file.
                &check_tx,
            );
        }
        Err(_) => {
            send_check_message(
                format!("Signature of manifest did not match the hash in the manifest.\n",)
                    .to_string(),
                false,
                &check_tx,
            );
        }
    };
    send_check_message(format!("{}", END_OF_MESSAGES).to_string(), false, &check_tx);

    let _res = writer_child.join();
}
