#![forbid(unsafe_code)]
use std::convert::TryInto;
use rand::prelude::ThreadRng;
//use std::io::Write;
use clap::{App, Arg};
use data_encoding::HEXUPPER;
use ring::digest::{Algorithm, Context, Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
use rand::Rng;
use scoped_threadpool::Pool;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use num_cpus;
use std::io::{BufReader, Read};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};


const PRIVATEKEY_LENGH_IN_BYTES: usize = 680;
const NONCE_LENGH_IN_BYTES: usize = 128;
const HASH_READ_BUUFER_IN_BYTES: usize = 8192;

fn main() {
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
                        .arg(Arg::with_name("private")
                            .short("i")
                            .long("private")
                            .value_name("FILE")
                            .help("This option allows for the user to set the location of the private key. I would reccomend placing it in a location where others can not read it. If not used, Signpriv.key is default. ")
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
                        .arg(Arg::with_name("files")
                             .value_name("FILES")
                             .help("Place one or more files to hash. Those that can not be found will be ommited from the results. Directories will be ommitted. Links will be treated like normal files.")
                               .required(true).min_values(1))
                        .get_matches();

    let hashalgo: &Algorithm;
    let inputhash = matches.value_of("algo").unwrap_or("256");
    //println!("Hash: {}", inputhash);
    match inputhash.as_ref() {
        "128" => hashalgo = &SHA1_FOR_LEGACY_USE_ONLY,
        "256" => hashalgo = &SHA256,
        "384" => hashalgo = &SHA384,
        "512" => hashalgo = &SHA512,
        _ => {
            panic!("Please choose 128, 256, 384 or 512 for type of SHA hash.");
        }
    }
    let private_key_file = matches.value_of("private").unwrap_or("Signpriv.key");
    let _manifest_file_name = matches.value_of("output").unwrap_or("Manifest.txt");
    let inputpool = matches.value_of("pool").unwrap_or("0");
    let poolresult = inputpool.parse();
    /*let _manifest_file = match File::open(& manifest_file_name){
        Err(why) => panic!("Couldn't open manifest file named {}: {}", manifest_file_name, why.description()),
        Ok(file) => file,
    };*/
    let mut poolnumber;
    match poolresult {
        Ok(n) => poolnumber = n,
        Err(_e) => {
            panic!("Please choose a number for the number of threads.");
        }
    }
    if poolnumber < 1  {
        poolnumber = num_cpus::get();
    }
    //println!("threads {}",poolnumber);
    let mut pool = Pool::new(poolnumber.try_into().unwrap());
    let (tx, rx): (
        Sender<String>,
        Receiver<String>,
    ) = mpsc::channel();
    let mut children = Vec::new();

    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    let num_files = inputfiles.len();
    let mut private_key_bytes: [u8; (PRIVATEKEY_LENGH_IN_BYTES/8)] = [0; (PRIVATEKEY_LENGH_IN_BYTES/8)];
    read_private_key(&mut private_key_bytes,private_key_file);
    let mut nonce_bytes: [u8; (NONCE_LENGH_IN_BYTES / 8)] = [0; (NONCE_LENGH_IN_BYTES / 8)];
    let rng = rand::thread_rng();
    let mut nonces: HashMap<[u8; NONCE_LENGH_IN_BYTES / 8], i32> = HashMap::new();
    pool.scoped(|scoped| {
        for file in inputfiles {
            let thread_tx = tx.clone();
            provide_unique_nonce(& mut nonce_bytes,& mut nonces,rng);
            let child = scoped.execute(move || {
                let _x = create_line(&file, hashalgo, &nonce_bytes, &private_key_bytes,thread_tx);
            });
            children.push(child);
        }
    });

    let mut strings = Vec::new();
    for _ in 0..num_files {
        // The `recv` method picks a message from the channel
        // `recv` will block the current thread if there are no messages available
        strings.push(rx.recv().unwrap());
    }

    // Show the order in which the messages were sent
    for _ in 0..strings.len() {
        println!("{}",strings.remove(0));
}
}

fn provide_unique_nonce(nonce_bytes: &mut [u8; 16], nonces: &mut std::collections::HashMap<[u8; 16], i32>, mut rng : ThreadRng ){
    let mut duplicate = true;
    let mut number :u8;
    while duplicate {
        duplicate = false;
        for x in 0..(NONCE_LENGH_IN_BYTES / 8) {
            number = rng.gen();
            nonce_bytes[x] = number;
        }
        if nonces.contains_key(nonce_bytes) {
            duplicate = true;
            eprintln!("//Duplicated nonce {} making a new one", HEXUPPER.encode(nonce_bytes));
        } else {
            nonces.insert(*nonce_bytes, 0);
        }
    }

}

fn read_private_key(private_key_bytes: &mut [u8], private_key_file: &str) {
    let mut file = match File::open(& private_key_file){
        Err(why) => panic!("Couldn't open private key file named {}: {}", private_key_file, why.description()),
        Ok(file) => file,
    };
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized_map: BTreeMap<String, String> = serde_yaml::from_str(&contents).unwrap();
    let local_key = match HEXUPPER.decode(deserialized_map["Private"].as_bytes()) {
        Err(why) => panic!("Couldn't decode hexencoded private key: {}", why.description()),
        Ok(local_key) => local_key,
    };
    for x in 0..(PRIVATEKEY_LENGH_IN_BYTES/8) {
        private_key_bytes[x] = local_key[x];
    }
}

fn var_digest<R: Read>(
    mut reader: R,
    hashalgo: &'static Algorithm,
) -> Digest {
    let mut context = Context::new(hashalgo);
    let mut buffer = [0; (HASH_READ_BUUFER_IN_BYTES/8)];

    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    context.finish()
}

fn sign_sigfile(path: &str, filen: u64, hash: &[u8], nonce: &[u8], private_key_bytes: &[u8]) -> ring::signature::Signature {
    let data = format!("{}:{}:{}:{}:", path, filen.to_string(),HEXUPPER.encode(&hash),HEXUPPER.encode(&nonce)) ;
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(private_key_bytes.as_ref()).unwrap();
    let sig = key_pair.sign(data.as_bytes());
    return sig;
}

fn create_line(path: &str, hashalgo: &'static Algorithm, nonce_bytes: &[u8], private_key_bytes : &[u8], tx : std::sync::mpsc::Sender<String>){
    let metadata = fs::metadata(path).unwrap();

    if !(metadata.is_dir()) {
        let filelen = metadata.len();
        let input = File::open(path).unwrap();
        let reader = BufReader::new(input);
        let digest = var_digest(reader, hashalgo);

        let signature = sign_sigfile(path, filelen, &digest.as_ref(), &nonce_bytes, &private_key_bytes);
        let data = format!("{}:{}:{}:{}:{}", path, filelen.to_string(),HEXUPPER.encode(&digest.as_ref()),HEXUPPER.encode(&nonce_bytes),HEXUPPER.encode(&signature.as_ref())) ;
        //println!("{}",data);
        tx.send(data).unwrap();
    }
    else {
        let data = format!("Directory: {}", path);
     //println!("{}",data);
     tx.send(data).unwrap();
    }
}
