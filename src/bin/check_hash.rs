#![forbid(unsafe_code)]
//use core::ptr::hash;
use clap::{App, Arg};
use data_encoding::HEXUPPER;
use ring::digest::{Algorithm, Context, Digest, SHA256, SHA384, SHA512};
use ring::signature;
use scoped_threadpool::Pool;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::process::exit;

fn main() {
    let matches = App::new("check_hash")
                          .version("0.1.0")
                          .author("Stephen Battista <stephen.battista@gmail.com>")
                          .about("Implements a signed hash for files")
                          .arg(Arg::with_name("algo")
                               .short("a")
                               .long("algorithm")
                               .value_name("256 | 384 | 512")
                               .help("Chooses what algorthim to use SHA256->(256), SHA384->(384) or SHA512->(512). Default is SHA256.")
                               .takes_value(true))
                          .arg(Arg::with_name("pool")
			        .short("p")
                               .long("pool")
                               .value_name("#")
                               .help("Sets the size of the pool of maximum number of concurrent threads when hashing. Default is 10. Large numbers (> 60) may cause the progam not to hash all files.")
                               .takes_value(true))
                          .arg(Arg::with_name("files")
                               .value_name("files")
                               .help("Place one or more files to hash. Those that can not be found will be ommited from the results. Directories will be ommitted. Links will be treated like normal files.")
                               .required(true).min_values(1))
                          .get_matches();

    let hashalgo: &Algorithm;
    let inputhash = matches.value_of("algo").unwrap_or("256");
    let hashlengh_in_bytes: usize;
    match inputhash.as_ref() {
        "256" => {
            hashalgo = &SHA256;
            hashlengh_in_bytes = 256;
        }
        "384" => {
            hashalgo = &SHA384;
            hashlengh_in_bytes = 384;
        }
        "512" => {
            hashalgo = &SHA512;
            hashlengh_in_bytes = 512;
        }
        _ => {
            println!("Please choose 256, 384 or 512 for type of SHA hash.");
            exit(0);
        }
    }
    //  println!("Hash chosen is {}", inputhash);

    let inputpool = matches.value_of("pool").unwrap_or("10");
    let poolresult = inputpool.parse();
    let poolnumber;
    match poolresult {
        Ok(n) => poolnumber = n,
        Err(_e) => {
            println!("Please choose a number for the number of threads.");
            exit(0);
        }
    }
    let mut pool = Pool::new(poolnumber);
    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    let inputfiles = inputfiles
        .into_iter()
        .filter(|&file| !(file.ends_with(".sig")))
        .collect::<Vec<_>>();

    pool.scoped(|scoped| {
        for file in inputfiles {
            scoped.execute(move || {
                let _x = gethashofile(&file, hashalgo, hashlengh_in_bytes);
            });
        }
    });
}

fn var_digest<R: Read>(
    mut reader: R,
    hashalgo: &'static Algorithm,
) -> Result<Digest, Box<dyn Error>> {
    let mut context = Context::new(hashalgo);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish())
}
fn read_sigfile(
    hash_from_file: &mut [u8],
    nonce: &mut [u8],
    filelen: &mut u64,
    path: &str,
    hashlengh_in_bytes: usize,
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

    for x in 0..(hashlengh_in_bytes / 8) {
        hash_from_file[x] = local_hash_vec[x];
    }
    let local_nonce_vec = HEXUPPER.decode(deserialized_map["NONCE"].as_bytes()).unwrap();
    for x in 0..(128 / 8) {
        nonce[x] = local_nonce_vec[x];
    }
    let local_sig_vec = HEXUPPER.decode(deserialized_map["SIG"].as_bytes()).unwrap();
    for x in 0..(512 / 8) {
        signed_hash[x] = local_sig_vec[x];
    }
}

fn read_public_key(public_key_bytes: &mut [u8]) {
    let mut file = File::open("Signpub.key").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized_map: BTreeMap<String, String> = serde_yaml::from_str(&contents).unwrap();
    //println!("{}",deserialized_map["Public"]);
    let local_key = HEXUPPER
        .decode(deserialized_map["Public"].as_bytes())
        .unwrap();
    for x in 0..32 {
        public_key_bytes[x] = local_key[x];
    }
}

fn gethashofile(
    path: &str,
    hashalgo: &'static Algorithm,
    hashlengh_in_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut hash_from_file = [0; 85];
    let mut filelen_from_file: u64 = 0;
    let metadata = fs::metadata(path).unwrap();
    let filelen = metadata.len();
    let mut signed_bytes = [0; 64];
    let mut nonce_bytes =[0;16];

    if !(metadata.is_dir()) {
        //println!("{}, {} ", path, &[path, ".sig"].concat());
        read_sigfile(
            &mut hash_from_file,
            &mut nonce_bytes,
            &mut filelen_from_file,
            &[path, ".sig"].concat(),
            hashlengh_in_bytes,
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
            for x in 0..(hashlengh_in_bytes / 8) {
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
                read_public_key(&mut public_key_bytes);
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
