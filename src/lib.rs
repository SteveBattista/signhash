#![forbid(unsafe_code)]

use rand::prelude::ThreadRng;
use rand::Rng;
use data_encoding::HEXUPPER;
//use std::convert::TryInto;
//use std::io::Write;
use chrono::{DateTime, Utc};
use pretty_bytes::converter::convert;

use ring::digest::{Algorithm, Context, Digest};
use std::collections::BTreeMap;
use std::collections::HashMap;

use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};

use std::time::Instant;


use ring::signature::KeyPair;

use std::io::prelude::*;

use serde_yaml;

pub const HEADER_MESSAGES: usize = 6;
pub const NONCE_LENGHT_IN_BYTES: usize = 128; // Chance of collistion is low 2^64. Progam checks for this.
pub const PRIVATEKEY_LENGH_IN_BYTES: usize = 680;
pub const PUBLICKEY_LENGH_IN_BYTES: usize = 256;

const HASH_READ_BUFFER_IN_BYTES: usize = 4096; //Emperical test finds this faster than 8192
const SEPERATOR : & 'static str = "********************************************************************************************************************";


pub struct Message {
    pub text: String,
    pub file_len: u64,
}

enum Whereoutput {
    FilePointer(File),
    StringText(String),
}

pub fn provide_unique_nonce(
    nonce_bytes: &mut [u8; 16],
    nonces: &mut HashMap<[u8; 16], i32>,
    mut rng: ThreadRng,
) {
    let mut duplicate = true;
    let mut number: u8;
    while duplicate {
        duplicate = false;
        for x in 0..(NONCE_LENGHT_IN_BYTES / 8) {
            number = rng.gen();
            nonce_bytes[x] = number;
        }
        if nonces.contains_key(nonce_bytes) {
            duplicate = true;
            eprintln!(
                "//Duplicated nonce {} making a new one",
                HEXUPPER.encode(nonce_bytes)
            );
        } else {
            nonces.insert(*nonce_bytes, 0);
        }
    }
}
fn write_line(wherefile: &mut Whereoutput, data: String){
    match wherefile{
        Whereoutput::FilePointer(ref mut file)  =>
        match file.write_all(data.as_bytes()) {
            Ok(_) => (),
            Err(why) => panic!(
                "Couldn't write {} to manifest: {}",
                data,
                why.description()
            )
        },
    Whereoutput::StringText(_string) => {
        print!("{}", data);
    }
};
}


pub fn write_from_channel(
    num_lines: usize,
    hashalgo: &'static Algorithm,
    private_key_bytes: &[u8],
    rx: std::sync::mpsc::Receiver<Message>,
    start: Instant,
    manifest_file: String
) {
    let mut context = Context::new(hashalgo);
    let mut byte_count = 0;
    let mut strings = Vec::new();
    let mut data: String;
    let mut total_file_len: u64 = 0;
    let mut message: Message;
    let mut wherefile: Whereoutput;
    let filepointer: File;
    if manifest_file == "|||"
    {
        wherefile= Whereoutput::StringText("STDIO".to_owned());
    } else {
         filepointer = match File::create(&manifest_file) {
            Ok(filepointer) => filepointer,
            Err(why) => panic!(
                "couldn't create manifestfile requested at {}: {}",
                manifest_file,
                why.description()
            )
        };
        wherefile = Whereoutput::FilePointer(filepointer);
    }

    for _ in 0..num_lines {
        // The `recv` method picks a message from the channel
        // `recv` will block the current thread if there are no messages available
        strings.push(rx.recv().unwrap());
        message = strings.remove(0);
        data = format!("{}", message.text);
        byte_count = byte_count + data.len();

        context.update(&data[..].as_bytes());
        total_file_len = total_file_len + message.file_len;
        write_line(& mut wherefile,  data);
    }
    let mut data = format!("{}\n", SEPERATOR);
    byte_count = byte_count + data.len();

    write_line(& mut wherefile,  data);

    let duration = start.elapsed();
    data = format!("C|Time elapsed was {:?}\n", duration);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(& mut wherefile,  data);

    data = format!("C|Total number of files is {:?}\n", num_lines - HEADER_MESSAGES);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(& mut wherefile,  data);

    data = format!("C|Total byte count of files in bytes is {:?}\n", total_file_len);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(& mut wherefile,  data);

    data = format!("C|Sum of size of files is {:?}\n", convert(byte_count as f64));
    context.update(data.as_bytes());
    write_line(& mut wherefile,  data);

    let digest = context.finish();
    data = format!("C|{}\n", HEXUPPER.encode(&digest.as_ref()));
    write_line(& mut wherefile,  data);

    let signature = sign_data(&HEXUPPER.encode(&digest.as_ref()), private_key_bytes);
    data = format!("C|{}\n", HEXUPPER.encode(&signature.as_ref()));
    write_line(& mut wherefile,  data);
}

fn sign_data(data: &str, private_key_bytes: &[u8]) -> ring::signature::Signature {
    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(private_key_bytes.as_ref()) {
        Ok(key_pair) => key_pair,
        Err(_why) => panic!("Couldn't load key pair from PKCS8 data."),
    };
    let sig = key_pair.sign(data.as_bytes());
    return sig;
}

pub fn read_private_key(private_key_bytes: &mut [u8], private_key_file: &str) {
    let mut file = match File::open(&private_key_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "Couldn't open private key file named {}: {}",
            private_key_file,
            why.description()
        ),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read private key file named {}: {}",
            private_key_file,
            why.description()
        ),
    };
    let deserialized_map: BTreeMap<String, String> = match serde_yaml::from_str(&contents) {
        Ok(deserialized_map) => (deserialized_map),
        Err(why) => panic!(
            "Couldn't parse private key YAML file in {}: {}",
            private_key_file,
            why.description()
        ),
    };
    let local_key = match HEXUPPER.decode(deserialized_map["Private"].as_bytes()) {
        Ok(local_key) => local_key,
        Err(why) => panic!(
            "Couldn't decode hexencoded private key: {}",
            why.description()
        ),
    };
    for x in 0..(PRIVATEKEY_LENGH_IN_BYTES / 8) {
        private_key_bytes[x] = local_key[x];
    }
}


pub fn dump_header(header_file: &str) -> String {
    let mut file = match File::open(&header_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "Couldn't open header file named {}: {}",
            header_file,
            why.description()
        ),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read header file named {}: {}",
            header_file,
            why.description()
        ),
    };
    return contents;
}


pub fn var_digest<R: Read>(mut reader: R, hashalgo: &'static Algorithm) -> Digest {
    let mut context = Context::new(hashalgo);
    let mut buffer = [0; (HASH_READ_BUFFER_IN_BYTES / 8)];

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(why) => panic!(
                "Couldn't load data from file to hash: {}",
                why.description()
            ),
        };
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    context.finish()
}


pub fn create_line(
    path: String,
    hashalgo: &'static Algorithm,
    nonce_bytes: &[u8],
    private_key_bytes: &[u8],
    tx: std::sync::mpsc::Sender<Message>,
) {
    let path2 = path.clone();
    let path3 = path.clone();
    let metadata = match fs::metadata(path) {
        Err(why) => panic!(
            "Couldn't load metadata from  {} data: {}",
            path2,
            why.description()
        ),
        Ok(metadata) => metadata,
    };
    let filelen = metadata.len();
    let datetime = match metadata.modified() {
        Err(why) => panic!(
            "Couldn't load datetime from  {} data: {}",
            path3,
            why.description()
        ),
        Ok(datetime) => datetime,
    };
    let datetime: DateTime<Utc> = datetime.into();
    let mut data: String;
    let signature: ring::signature::Signature;

    if !(metadata.is_dir()) {
        let input = match File::open(path2) {
            Ok(input) => input,
            Err(why) => panic!("Couldn't file {}: {}", path3, why.description()),
        };
        let reader = BufReader::new(input);
        let digest = var_digest(reader, hashalgo);
        data = format!(
            "File|{}|{}|{}|{}|{}",
            path3,
            filelen,
            datetime.format("%d/%m/%Y %T"),
            HEXUPPER.encode(&digest.as_ref()),
            HEXUPPER.encode(&nonce_bytes)
        );
    } else {
        data = format!(
            "Dir|{}|{}|{}|{}",
            path3,
            filelen,
            datetime.format("%d/%m/%Y %T"),
            HEXUPPER.encode(&nonce_bytes)
        );
    }
    signature = sign_data(&data, &private_key_bytes);
    data = format!("{}|{}\n", data, HEXUPPER.encode(&signature.as_ref()));
    let mut message = Message {
        text: String::new(),
        file_len: 0,
    };
    message.text = data;
    message.file_len = filelen;
    match tx.send(message) {
        Ok(input) => input,
        Err(why) => panic!("Couldn't send message {}", why.description()),
    };
}

pub fn create_keys(public_key_bytes: &mut [u8], private_key_bytes: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng) {
        Err(_) => panic!("Couldn't create pks8 key"),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
        Err(_) => panic!("Couldn't create keypair from pks8 key."),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    for x in 0..(PUBLICKEY_LENGH_IN_BYTES / 8) {
        public_key_bytes[x] = key_pair.public_key().as_ref()[x];
    }
    for x in 0..(PRIVATEKEY_LENGH_IN_BYTES / 8) {
        private_key_bytes[x] = pkcs8_bytes.as_ref()[x];
    }
}

pub fn write_key(public_key_bytes: &[u8], pubic_key_file: &str, key_name: &str) {
    let mut map = BTreeMap::new();
    map.insert(key_name.to_string(), HEXUPPER.encode(&public_key_bytes));
    let s = match serde_yaml::to_string(&map) {
        Ok(s) => s,
        Err(_) => panic!("Couldn't create YMAL string for {} key.", key_name),
    };
    let mut file = match File::create(&pubic_key_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "couldn't create {} key at {}: {}",
            key_name,
            pubic_key_file,
            why.description()
        )

    };
    match file.write_all(s.as_bytes()) {
        Ok(_) => (),
        Err(why) => panic!(
            "Couldn't write to {} key to {}: {}",
            key_name,
            pubic_key_file,
            why.description()
        )
    };
}

pub fn write_keys(
    public_key_bytes: &[u8],
    private_key_bytes: &[u8],
    public_key_file: &str,
    private_key_file: &str,
) {
    write_key(&public_key_bytes, public_key_file, "Public");
    write_key(&private_key_bytes, private_key_file, "Private");
}

pub fn write_headers(tx: &std::sync::mpsc::Sender<Message>, inputhash: &str, command_line : &str, header_file : & str, now : &chrono::DateTime<Utc>, poolnumber: usize,  ){

    let mut message = Message {
    text: String::new(),
    file_len: 0,
};
message.text = format!("C|{}\n",&inputhash).to_string();
message.file_len = 0;
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send hash type to writing thread. : {}",
        why.description()
    ),
};

let mut message = Message {
    text: String::new(),
    file_len: 0,
};
message.text = format!("C|{}\n",&command_line).to_string();
message.file_len = 0;
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send command line to writing thread. : {}",
        why.description()
    ),
};

let mut message = Message {
    text: String::new(),
    file_len: 0,
};
if header_file == "|||" {
    message.text = "C|No Header File\n".to_string();
} else {
    message.text = dump_header(header_file);
}
message.file_len = 0;
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send header file to writing thread. : {}",
        why.description()
    ),
};

let mut message = Message {
    text: String::new(),
    file_len: 0,
};
message.text = format!("C|Start time was {}\n", now.to_string());
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send start time to writing thread. : {}",
        why.description()
    ),
};

let mut message = Message {
    text: String::new(),
    file_len: 0,
};
message.text = format!("C|Threads for main hashing was {}\n", poolnumber);
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send number of threads message to writing thread. : {}",
        why.description()
    ),
};

let mut message = Message {
    text: String::new(),
    file_len: 0,
};
message.text = format!("{}\n",SEPERATOR);
match tx.send(message) {
    Ok(_x) => (),
    Err(why) => panic!(
        "Couldn't send seprator to writing thread. : {}",
        why.description()
    ),
};
}
