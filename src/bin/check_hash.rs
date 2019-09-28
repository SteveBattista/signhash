#![forbid(unsafe_code)]

use chrono::Utc;
use chrono::DateTime;
use std::error::Error;
use ring::digest::SHA256;
use signhash::parse_hash_manifest_line;
use signhash::read_public_key;
use signhash::write_check_from_channel;


use signhash::CheckMessage;
use signhash::parse_next_manifest_line;
use signhash::report_duplicatve_and_insert_nonce;
use signhash::ManifestLine;
//use signhash::create_line;
use signhash::read_manifest_file;
use signhash::NONCE_LENGTH_IN_BYTES;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::SEPERATOR;
use signhash::CHECK_HEADER_MESSAGE_COUNT;

use scoped_threadpool::Pool;
use std::convert::TryInto;

use num_cpus;
use std::thread;
use std::env;

use clap::{App, Arg};
//use chrono::{DateTime, Utc};

use ring::digest::{Algorithm, Context};

use std::collections::HashMap;
//use std::env;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
//use std::time::Instant;

//use std::io::Write;
//use std::io::stdout;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

use walkdir::WalkDir;

const BITS_IN_HEX: usize = 16;

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
                          .get_matches();

    let mut public_key_bytes: [u8; (PUBLICKEY_LENGTH_IN_BYTES / 8)] =
        [0; (PUBLICKEY_LENGTH_IN_BYTES / 8)];
    let public_key_file = matches.value_of("public").unwrap_or("Signpub.key");
    read_public_key(public_key_file, &mut public_key_bytes);

    let output_file = matches.value_of("output").unwrap_or("|||").to_string();

    let mut fileoutput = true;
    if output_file == "|||" {
        fileoutput = false;
    }

    let input_file = matches
        .value_of("input")
        .unwrap_or("Manifest.txt")
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
    let (tx, rx): (Sender<CheckMessage>, Receiver<CheckMessage>) = mpsc::channel();

    let input_directoy = matches.value_of("directory").unwrap_or(".");

    let mut inputfiles: Vec<String> = Vec::new();
    let spinner = ProgressBar::new_spinner();
    if fileoutput {
        spinner.set_prefix("Constucting file list time:");
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
    let num_files = inputfiles.len();

    let nonce_bytes: [u8; (NONCE_LENGTH_IN_BYTES / 8)] = [0; (NONCE_LENGTH_IN_BYTES / 8)];
    let rng = rand::thread_rng();
    let mut nonces: HashMap<[u8; NONCE_LENGTH_IN_BYTES / 8], i32> = HashMap::new();



    let mut version_line = vec_of_lines.remove(0);
    let mut command_line = vec_of_lines.remove(0);
    let mut hash_line = vec_of_lines.remove(0);

    let hashalgo: &Algorithm = &SHA256;
    parse_hash_manifest_line(&hash_line, hashalgo);

    let mut hashlength_in_bytes: usize = hashalgo.output_len * BITS_IN_HEX;

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

    let mut reading_header = true;
    let mut next_line :String;
    while reading_header {
        next_line = vec_of_lines.remove(0);
        reading_header = next_line == SEPERATOR;
        next_line = next_line + "\n";
        file_hash_context.update(next_line.as_bytes());
        file_len = file_len + next_line.len();
    }
    let bar = ProgressBar::new(inputfiles.len().try_into().unwrap());
    if fileoutput {
        bar.set_prefix("Number of Files Checked");
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {wide_bar} {pos}/{len} {elapsed_precise}"),
        );
    }

    let writer_child = thread::spawn(move || {
        write_check_from_channel(num_files + CHECK_HEADER_MESSAGE_COUNT, rx, output_file, &bar, fileoutput);
    });

    let mut message = CheckMessage {
        text: String::new(),
        verbose: true,
    };
    message.text = format!("Command Line |{}\n", args.join(" "));
    match tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send arguments to writing thread. : {}",
            why.description()
        ),
    };

    let mut message = CheckMessage {
        text: String::new(),
        verbose: true,
    };
    message.text = format!("Start time was |{}\n", now.to_string());
    match tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send arguments to writing thread. : {}",
            why.description()
        ),
    };

    let mut message = CheckMessage {
        text: String::new(),
        verbose: true,
    };
    message.text = format!("Threads used for main hashing was |{}\n", poolnumber);
    match tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send number of threads message to writing thread. : {}",
            why.description()
        ),
    };

    let mut message = CheckMessage {
        text: String::new(),
        verbose: true,
    };

    message.text = format!("Hash size|{}\n", &hashalgo.output_len).to_string();
    match tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send hash type to writing thread. : {}",
            why.description()
        ),
    };

    let mut message = CheckMessage {
        text: String::new(),
        verbose: true,
    };
    message.text = format!("Signature algorthim |ED25519\n").to_string();
    match tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send signture type to writing thread. : {}",
            why.description()
        ),
    };


    let type_of_line = String::new();
    let file_name_line= String::new();
    let bytes_line= String::new();
    let time_line= String::new();
    let nonce_line = String::new();
    let hash_line = String::new();
    let sign_line = String::new();
    let mut manifest_line=vec_of_lines.remove(0);
    let mut working_on_files = true;
    if manifest_line == SEPERATOR{
        working_on_files =false;
        manifest_line = manifest_line + "/n";
        file_hash_context.update(manifest_line.as_bytes());
        file_len = file_len + manifest_line.len();
    }
    let nonces: &mut HashMap<String, String> = &mut HashMap::new();
    let manifest_map : &mut HashMap<String,ManifestLine> = &mut HashMap::new();
    while working_on_files{
    parse_next_manifest_line(manifest_line.clone(),type_of_line.clone(),file_name_line.clone(),bytes_line.clone(),time_line.clone(),hash_line.clone(),nonce_line.clone(),sign_line.clone());
    manifest_line = manifest_line + "/n";
    file_hash_context.update(manifest_line.as_bytes());
    file_len = file_len + manifest_line.len();
    report_duplicatve_and_insert_nonce(nonces,nonce_line.clone(),file_name_line.clone(),tx.clone());

    let manifist_line = ManifestLine {
        file_type: type_of_line.clone(),
        bytes: bytes_line.clone(),
        time: time_line.clone(),
        hash: hash_line.clone(),
        nonce: nonce_line.clone(),
        sign: sign_line.clone(),
    };
    manifest_map.insert(file_name_line.clone(),manifist_line);
    manifest_line = vec_of_lines.remove(0);
    if manifest_line == SEPERATOR{
        working_on_files =false;
        manifest_line = manifest_line + "/n";
        file_hash_context.update(manifest_line.as_bytes());
        file_len = file_len + manifest_line.len();
    }
}


    pool.scoped(|scoped| {
        for file in inputfiles {
            match manifest_map.remove(&file) {
             Some(_file_line) => {
                 scoped.execute(move || {
             //        let _x = compare_lines(&file, hashalgo, hashlength_in_bytes);
                 });
             },
             None => {
                 let mut message = CheckMessage {
                     text: String::new(),
                     verbose: false,
                 };
                 message.text = format!("{} was in the manifest but not found in direcorty search\n",file);
                 match tx.send(message) {
                     Ok(_x) => (),
                     Err(why) => panic!(
                         "Couldn't send non found file to writing thread. : {}",
                         why.description()
                     ),
                 };
     },
 };

        }
    });

    if manifest_map.len() > 0 {
        for (file_line, _manifest_structure) in manifest_map.drain().take(1) {
        let mut message = CheckMessage {
                text: String::new(),
                verbose: true,
            };
            message.text = format!("{} was in the manifest but not found in direcorty search\n",file_line);
            match tx.send(message) {
                Ok(_x) => (),
                Err(why) => panic!(
                    "Couldn't send non found file to writing thread. : {}",
                    why.description()
                ),
            };
}
    }


    // pass elasped Time
    // check number of Files
    // check total files size
    // pass Speed
    //check average
    //pass nonce
    // check size of file so far
    //gen hash and check it
    //check sig
    //send an ending message


    let _res = writer_child.join();
}

/*
fn read_sigfile(
    hash_from_file: &mut [u8],
    nonce: &mut [u8],
    filelen: &mut u64,
    path: &str,
    hashlength_in_bytes: usize,
    signed_hash: &mut [u8],
) {
    let mut file = File::open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized_map: BTreeMap<String, String> = serde_yaml::from_str(&contents).unwrap();
    let local_hash_vec = HEXUPPER
        .decode(deserialized_map["HASH"].as_bytes())
        .unwrap();
    *filelen = deserialized_map["LENGTH"].parse::<u64>().unwrap();

    for x in 0..(hashlength_in_bytes / 8) {
        hash_from_file[x] = local_hash_vec[x];
    }
    let local_nonce_vec = HEXUPPER
        .decode(deserialized_map["NONCE"].as_bytes())
        .unwrap();
    for x in 0..(128 / 8) {
        nonce[x] = local_nonce_vec[x];
    }
    let local_sig_vec = HEXUPPER.decode(deserialized_map["SIG"].as_bytes()).unwrap();
    for x in 0..(512 / 8) {
        signed_hash[x] = local_sig_vec[x];
    }
}
*/
