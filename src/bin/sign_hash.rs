#![forbid(unsafe_code)]
use std::convert::TryInto;
use rand::prelude::ThreadRng;
use std::thread;
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
use chrono::{DateTime, Utc};
use std::env;
use std::time::{Instant};
use pretty_bytes::converter::convert;

struct Message {
    text: String,
    file_len: u64,
}

const HEADER_MESSAGES: usize = 4;
const PRIVATEKEY_LENGH_IN_BYTES: usize = 680;
const NONCE_LENGH_IN_BYTES: usize = 128; // Chance of collistion is low 2^64. Progam checks for this.
const HASH_READ_BUUFER_IN_BYTES: usize = 4096; //Emperical test finds this faster than 8192
const SEPERATOR : & 'static str = "********************************************************************************************************************";

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
    /*let _manifest_file = match File::open(& manifest_file_name){
        Err(why) => panic!("Couldn't open manifest file named {}: {}", manifest_file_name, why.description()),
        Ok(file) => file,
    };*/
    let inputpool = matches.value_of("pool").unwrap_or("0");
    let poolresult = inputpool.parse();
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

    let mut pool = Pool::new(poolnumber.try_into().unwrap());
    let (tx, rx): (
        Sender<Message>,
        Receiver<Message>,
    ) = mpsc::channel();
    let mut children = Vec::new();

    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    let num_files = inputfiles.len();
    let mut private_key_bytes: [u8; (PRIVATEKEY_LENGH_IN_BYTES/8)] = [0; (PRIVATEKEY_LENGH_IN_BYTES/8)];
    read_private_key(&mut private_key_bytes,private_key_file);
    let mut nonce_bytes: [u8; (NONCE_LENGH_IN_BYTES / 8)] = [0; (NONCE_LENGH_IN_BYTES / 8)];
    let rng = rand::thread_rng();
    let mut nonces: HashMap<[u8; NONCE_LENGH_IN_BYTES / 8], i32> = HashMap::new();
    let command_line  = args.join(" ");
    let mut message = Message {
        text: String::new(),
        file_len: 0,
    };
    message.text = command_line.to_string();
    message.file_len =0;
    tx.send(message).unwrap();
    let mut message = Message {
        text: String::new(),
        file_len: 0,
    };
    message.text = format!("Start time was {}",now.to_string());
    tx.send(message).unwrap();
    let mut message = Message {
        text: String::new(),
        file_len: 0,
    };
    message.text = format!("Threads for main hashing was {}",poolnumber);

    tx.send(message).unwrap();
    let mut message = Message {
        text: String::new(),
        file_len: 0,
    };
    message.text = SEPERATOR.to_string();
    tx.send(message).unwrap();
    let writer_child = thread::spawn(move || {
    write_from_channel(num_files + HEADER_MESSAGES ,hashalgo, &private_key_bytes, rx, start );
 });

    pool.scoped(|scoped| {
        for file in inputfiles {
            let thread_tx = tx.clone();
            provide_unique_nonce(& mut nonce_bytes,& mut nonces,rng);
            let child = scoped.execute(move || {
                let _x = create_line(file.to_string(), hashalgo, &nonce_bytes, &private_key_bytes,thread_tx);
            });
            children.push(child);
        }
    });

let _res = writer_child.join();


}

fn write_from_channel(num_lines : usize, hashalgo : &'static Algorithm, private_key_bytes : &[u8], rx : std::sync::mpsc::Receiver<Message>, start: Instant) {
    let mut context = Context::new(hashalgo);
    let mut byte_count = 0;
    let mut strings = Vec::new();
    let mut data :String;
    let mut total_file_len :u64 =0;
    let mut message : Message;
    for _ in 0..num_lines {
        // The `recv` method picks a message from the channel
        // `recv` will block the current thread if there are no messages available
        strings.push(rx.recv().unwrap());
        message = strings.remove(0);
        data = format!("{}",message.text);
        byte_count = byte_count + data.len();
        println!("{}", data);
        context.update(&data[..].as_bytes());
        total_file_len = total_file_len + message.file_len;

    }
    let mut data = format!("{}", SEPERATOR);
    println!("{}",data);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());

    let duration = start.elapsed();
    data  = format!("Time elapsed was {:?}", duration);
    println!("{}",data);
    byte_count = byte_count + data.len();


    data  = format!("Total number of files is {:?}", num_lines-HEADER_MESSAGES);
    println!("{}",data);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());

    data  = format!("Total byte count of files is {:?}", convert(total_file_len as f64));
    println!("{}",data);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());


    data  = format!("Byte count of output is {:?}", convert(byte_count as f64));
    println!("{}",data);
    context.update(data.as_bytes());

    let digest = context.finish();
    println!("{}",HEXUPPER.encode(&digest.as_ref()));

    let signature = sign_data(&HEXUPPER.encode(&digest.as_ref()),  private_key_bytes);
    println!("{}", HEXUPPER.encode(&signature.as_ref()));
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

fn sign_data(data: &str,  private_key_bytes: &[u8]) -> ring::signature::Signature {
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(private_key_bytes.as_ref()).unwrap();
    let sig = key_pair.sign(data.as_bytes());
    return sig;
}

fn create_line(path: String, hashalgo: &'static Algorithm, nonce_bytes: &[u8], private_key_bytes : &[u8], tx : std::sync::mpsc::Sender<Message>){
    let path2 =path.clone();
    let path3 =path.clone();
    let metadata = fs::metadata(path).unwrap();
    let filelen = metadata.len();
    let datetime = metadata.modified().unwrap();
    let datetime: DateTime<Utc> = datetime.into();
    let mut data :String;
    let signature : ring::signature::Signature;

    if !(metadata.is_dir()) {
        let input = File::open(path2).unwrap();
        let reader = BufReader::new(input);
        let digest = var_digest(reader, hashalgo);
        data = format!("File|{}|{}|{}|{}|{}", path3, convert(filelen as f64),datetime.format("%d/%m/%Y %T"),HEXUPPER.encode(&digest.as_ref()),HEXUPPER.encode(&nonce_bytes)) ;
    }
    else {
        data = format!("Dir|{}|{}|{}|{}", path3,convert(filelen as f64),datetime.format("%d/%m/%Y %T"),HEXUPPER.encode(&nonce_bytes));

    }
        signature = sign_data(&data, &private_key_bytes);
        data = format!("{}|{}", data,HEXUPPER.encode(&signature.as_ref()));
        let mut message = Message {
            text: String::new(),
            file_len: 0,
        };
        message.text = data;
        message.file_len = filelen;
        tx.send(message).unwrap();

}
