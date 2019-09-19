#![forbid(unsafe_code)]


use signhash::write_key;
use signhash::create_keys;
use signhash::write_headers;
use signhash::provide_unique_nonce;
use signhash::write_from_channel;
use signhash::Message;
use signhash::create_line;
use signhash::PRIVATEKEY_LENGTH_IN_BYTES;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::NONCE_LENGTH_IN_BYTES;



use std::convert::TryInto;
use scoped_threadpool::Pool;

use num_cpus;
use std::thread;

use clap::{App, Arg};
use chrono::{DateTime, Utc};

use ring::digest::{Algorithm, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};

use std::collections::HashMap;
use std::env;

use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;


fn main() {
    let now: DateTime<Utc> = Utc::now();
    let start = Instant::now();
    let args: Vec<String> = env::args().collect();
    let matches = App::new("sign_hash")
                          .version("0.1.0")
                          .author("Stephen Battista <stephen.battista@gmail.com>")
                          .about("Implements a signed hash for files")
                          .arg(Arg::with_name("algo")
                               .short("a")
                               .long("algorithm")
                               .value_name("128| 256 | 384 | 512")
                               .help("Chooses what algorthim to use SHA1 -> (128), SHA256->(256), SHA384->(384) or SHA512->(512). Default is SHA256. Please don't use SHA1 unless you are using it to line up with threat intelgence.")
                               .takes_value(true))
                          .arg(Arg::with_name("public")
                                .short("u")
                                .long("public")
                                .value_name("FILE")
                                .help("This option allows for the user to set the location of the public key. If not used, Signpub.key is default.")
                                .takes_value(true))
                        .arg(Arg::with_name("output")
                            .short("o")
                            .long("output")
                            .value_name("FILE")
                            .help("This option allows for the user to set the location of the manifest file.  If not used, Manifest.txt is default. ")
                            .takes_value(true))
                        .arg(Arg::with_name("pool")
     			            .short("p")
                            .long("pool")
                            .value_name("#")
                            .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is number of CPU cores. Negative numbers set pool to default. Warning: Large numbers (> 60) may cause the progam not to hash all files.")
                            .takes_value(true))
                            .arg(Arg::with_name("header")
         			            .short("h")
                                .long("header")
                                .value_name("FILE")
                                .help("Name of file that you would like to include in the header.")
                                .takes_value(true))
                        .arg(Arg::with_name("files")
                             .value_name("FILES")
                             .help("Place one or more files to hash. Those that can not be found will be ommited from the results. Directories will be ommitted. Links will be treated like normal files.")
                               .required(true).min_values(1))
                        .get_matches();

    let hashalgo: &Algorithm;
    let inputhash = matches.value_of("algo").unwrap_or("256");
    match inputhash.as_ref() {
        "128" => hashalgo = &SHA1_FOR_LEGACY_USE_ONLY,
        "256" => hashalgo = &SHA256,
        "384" => hashalgo = &SHA384,
        "512" => hashalgo = &SHA512,
        _ => {
            panic!("Please choose 128, 256, 384 or 512 for type of SHA hash.");
        }
    }
    let manifest_file = matches.value_of("output").unwrap_or("|||").to_string();

    let public_key_file = matches.value_of("public").unwrap_or("Signpub.key");

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

    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();
    let mut children = Vec::new();

    let header_file = matches.value_of("header").unwrap_or("|||");


    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    let num_files = inputfiles.len();
    let mut private_key_bytes: [u8; (PRIVATEKEY_LENGTH_IN_BYTES / 8)] =
        [0; (PRIVATEKEY_LENGTH_IN_BYTES / 8)];
    let mut public_key_bytes: [u8; (PUBLICKEY_LENGTH_IN_BYTES / 8)] =
            [0; (PUBLICKEY_LENGTH_IN_BYTES / 8)];

    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    write_key(&public_key_bytes, public_key_file, "Public");

    let mut nonce_bytes: [u8; (NONCE_LENGTH_IN_BYTES / 8)] = [0; (NONCE_LENGTH_IN_BYTES / 8)];
    let rng = rand::thread_rng();
    let mut nonces: HashMap<[u8; NONCE_LENGTH_IN_BYTES / 8], i32> = HashMap::new();


    write_headers(&tx,inputhash,&args.join(" "),header_file,&now,poolnumber);

    let writer_child = thread::spawn(move || {
        write_from_channel(
            num_files + signhash::HEADER_MESSAGES,
            hashalgo,
            &private_key_bytes,
            rx,
            start,
            manifest_file,
        );
    });

    pool.scoped(|scoped| {
        for file in inputfiles {
            let thread_tx = tx.clone();
            provide_unique_nonce(&mut nonce_bytes, &mut nonces, rng);
            let child = scoped.execute(move || {
                let _x = create_line(
                    file.to_string(),
                    hashalgo,
                    &nonce_bytes,
                    &private_key_bytes,
                    thread_tx,
                );
            });
            children.push(child);
        }
    });

    let _res = writer_child.join();
}
