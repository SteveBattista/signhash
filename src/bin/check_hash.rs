#![forbid(unsafe_code)]

use signhash::parse_hash_manifest_line;
use signhash::read_public_key;
//use signhash::write_from_channel;
use signhash::CheckMessage;
//use signhash::create_line;
use signhash::read_manifest_file;
use signhash::NONCE_LENGTH_IN_BYTES;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::SEPERATOR;

use scoped_threadpool::Pool;
use std::convert::TryInto;

use num_cpus;
use std::thread;

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
        //println!("{}", entry.unwrap().path().display());
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

    let hashalgo: &Algorithm;
    let mut file_len: usize = 0;
    let version_line = vec_of_lines.remove(0);
    let command_line = vec_of_lines.remove(0);
    let mut hash_line = vec_of_lines.remove(0);
    let mut hashlength_in_bytes: usize;

    parse_hash_manifest_line(&hash_line, hashalgo);
    let hashlength_in_bytes: usize = hashalgo.output_len * BITS_IN_HEX;

    let mut file_hash_context = Context::new(hashalgo);

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
    let mut next_line = String::new();
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
        write_check_from_channel(hashalgo, rx, output_file, &bar, fileoutput);
    });
    let mut working_on_files = true;
    //parse_next_manifest_line
    // find line in manifest to match current file, if not in manifest send message to writer and go to next one
    //Check for duplicate nonce, if so send message to the writer
    //scope this to items until next seprator
    pool.scoped(|scoped| {
        for file in inputfiles {
            scoped.execute(move || {
                //let _x = compare_lines(&file, hashalgo, hashlength_in_bytes);
            });
        }
    });
    let _res = writer_child.join();
    //for each leftover file/directory send message

    //SEPERATOR
    // pass elasped Time
    // check number of Files
    // check total files size
    // pass Speed
    //check average
    //pass nonce
    // check size of file so far
    //gen hash and check it
    //check sig

    //send ending message
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


fn gethashofile(
    path: &str,
    hashalgo: &'static Algorithm,
    hashlength_in_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut hash_from_file = [0; 85];
    let mut filelen_from_file: u64 = 0;
    let metadata = fs::metadata(path).unwrap();
    let filelen = metadata.len();
    let mut signed_bytes = [0; 64];
    let mut nonce_bytes = [0; 16];

    if !(metadata.is_dir()) {
        //println!("{}, {} ", path, &[path, ".sig"].concat());
        read_sigfile(
            &mut hash_from_file,
            &mut nonce_bytes,
            &mut filelen_from_file,
            &[path, ".sig"].concat(),
            hashlength_in_bytes,
            &mut signed_bytes,
        );
        //println!("here");
        if filelen != filelen_from_file {
            eprintln!("File {} failed length check.", path);
        } else {
            let input = File::open(path)?;
            let reader = BufReader::new(input);
            //println!("BufReader");
            let digest = var_digest(reader, hashalgo)?;
            let mut hash_match = true;
            for x in 0..(hashlength_in_bytes / 8) {
                if hash_from_file[x] != digest.as_ref()[x] {
                    eprintln!("File {} failed hash check.", path);
                    hash_match = false;
                    break;
                }
            }
            if hash_match {
                /*eprintln!(
                "File {} passed hash check.",
                path); */
                let mut public_key_bytes: [u8; 32] = [0; 32];
                //println!("readpublickey");

                //println!("{}",HEXUPPER.encode(&signed_bytes));
                let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
                let data = format!(
                    "{}:{}:{}",
                    HEXUPPER.encode(&digest.as_ref()),
                    filelen.to_string(),
                    HEXUPPER.encode(&nonce_bytes)
                );
                //println!("{}",data);
                let results = peer_public_key.verify(data.as_bytes(), signed_bytes.as_ref());
                match results {
                    Ok(_n) => (), //eprintln!( "File {} passed.",path),
                    Err(_err) => eprintln!("File {}.sig failed signature check.", path),
                }
            }
        }
    }
    Ok(())
}
*/
