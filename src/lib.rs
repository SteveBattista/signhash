#![forbid(unsafe_code)]

use data_encoding::HEXUPPER;
use rand::prelude::ThreadRng;
use rand::Rng;

use chrono::{DateTime, Utc};

use ring::digest::{Algorithm, Context, Digest};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
use std::collections::BTreeMap;
use std::collections::HashMap;

use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::Write;
use std::io::{BufReader, Read};

use std::time::Instant;

use ring::signature::KeyPair;

use serde_yaml;

use indicatif::HumanBytes;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;

pub const SIGN_HEADER_MESSAGE_COUNT: usize = 8;

pub const NONCE_LENGTH_IN_BYTES: usize = 128; // Chance of collision is low 2^64. Program checks for this.
pub const PRIVATEKEY_LENGTH_IN_BYTES: usize = 680;
pub const PUBLICKEY_LENGTH_IN_BYTES: usize = 256;
pub const SIGNED_LENGTH_IN_BYTES: usize = 512;

const HASH_READ_BUFFER_IN_BYTES: usize = 4096; //Empirical test finds this faster than 8192
pub const SEPARATOR: &str =
    "********************************************************************************"; //80 stars
const NO_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const PUBIC_KEY_STRING_ED25519: &'static str = "Public ED25519";
pub const PRIVATE_KEY_STRING_ED25519: &'static str = "Private ED25519";
pub const DEFAULT_MANIFEST_FILE_NAME: &'static str = "Manifest.txt";
pub const DEFAULT_PUBIC_KEY_FILE_NAME: &'static str = "Signpub.txt";
//pub const END_OF_MESSAGES : & str = "87e00106e0c012cd1c0216292d070989125c3f215b73429fa8a3f247b8520f3110e53db9d4e139328ba8f00321117fbda14bb317ee498909a393fafce4bd631e7966f4be302d1818b12bf22e32c38fc4cc594c310c2de480df29b2ca3a4b2c470eb0610e309740ef831f18969c9fc97f7d7dfc8d98110b5f8064393605b1e20110dc90bd9d20e87a32e5fbd611bf071bf61d8fb1a1c0352ff82974b989ea91e9
//03eb1e75831a7bd4f3aebce5857bfcb7cf917b948caea4ea7e8530938818449cc8856c039599e757b437ab94f2818c8a91cf669abe6abbb629ed651301f4a86ea218d128451dabc5b06ccdd38e8a729c00458e7c9b777a33db51d2f61047444";
//random 256 bit message :) I know someone is going do decomplie this and think that it is some built in key :)
pub const PRINT_MESSAGE :u8 = 0;
pub const TICK_MESSAGE :u8 = 1;
pub const END_MESSAGE :u8 =2;

pub struct SignMessage {
    pub text: String,
    pub file_len: u64,
}

pub struct CheckMessage {
    pub check_type :u8,
    pub text: String,
    pub verbose: bool,
}

pub enum Whereoutput {
    FilePointer(File),
    StringText(String),
}

pub struct ManifestLine {
    pub file_type: String,
    pub bytes: String,
    pub time: String,
    pub hash: String,
    pub nonce: String,
    pub sign: String,
}

pub fn report_duplicatve_and_insert_nonce(
    nonces: &mut HashMap<String, String>,
    nonce: String,
    file_name_line: String,
    check_tx: std::sync::mpsc::Sender<CheckMessage>,
) {
    match nonces.insert(nonce.clone(), file_name_line) {
        None => (),
        Some(answer) => {
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "Suspect replay attack as |{}|and|{}|share the same nonce.\n",
                    nonce.clone(),
                    answer
                )
                .to_string(),
                false,
                &check_tx,
            );
        }
    };
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
        for x in 0..(NONCE_LENGTH_IN_BYTES / 8) {
            number = rng.gen();
            nonce_bytes[x] = number;
        }
        if nonces.contains_key(nonce_bytes) {
            duplicate = true;
            eprintln!(
                "!!Duplicated nonce|{}|making a new one.",
                HEXUPPER.encode(nonce_bytes)
            );
        } else {
            nonces.insert(*nonce_bytes, 0);
        }
    }
}

pub fn write_check_from_channel(
    verbose: bool,
    check_rx: std::sync::mpsc::Receiver<CheckMessage>,
    output_file: String,
    fileoutput: bool,
    bar: ProgressBar,
) {
    let mut message: CheckMessage;
    let mut wherefile: Whereoutput;
    let filepointer: File;
    if !fileoutput {
        wherefile = Whereoutput::StringText("STDIO".to_owned());
    } else {
        filepointer = match File::create(&output_file) {
            Ok(filepointer) => filepointer,
            Err(why) => panic!(
                "couldn't create check file requested at|{}|{}",
                output_file,
                why.description()
            ),
        };
        wherefile = Whereoutput::FilePointer(filepointer);
    }
    message = check_rx.recv().unwrap();
    while message.check_type != END_MESSAGE {
        if message.check_type == TICK_MESSAGE{
            if fileoutput {
                bar.inc(1);
            }
        } else {
            if verbose {
                write_line(&mut wherefile, message.text);
            } else if message.verbose == false {
                write_line(&mut wherefile, message.text);
            }

        }
        message = check_rx.recv().unwrap();
    }
    if fileoutput {
        bar.finish();
    }
}

pub fn write_line(wherefile: &mut Whereoutput, data: String) {
    match wherefile {
        Whereoutput::FilePointer(ref mut file) => match file.write_all(data.as_bytes()) {
            Ok(_) => (),
            Err(why) => panic!(
                "Couldn't write|{}|to the manifest file|{}.",
                data,
                why.description()
            ),
        },
        Whereoutput::StringText(_string) => {
            print!("{}", data);
        }
    };
}

pub fn write_manifest_from_channel(
    num_lines: usize,
    hashalgo: &'static Algorithm,
    private_key_bytes: &[u8],
    rx: std::sync::mpsc::Receiver<SignMessage>,
    start: Instant,
    manifest_file: String,
    bar: &ProgressBar,
    fileoutput: bool,
) {
    let mut context = Context::new(hashalgo);
    let mut byte_count = 0;
    let mut data: String;
    let mut total_file_len: u64 = 0;
    let mut message: SignMessage;
    let mut wherefile: Whereoutput;
    let filepointer: File;
    if manifest_file == "|||" {
        wherefile = Whereoutput::StringText("STDIO".to_owned());
    } else {
        filepointer = match File::create(&manifest_file) {
            Ok(filepointer) => filepointer,
            Err(why) => panic!(
                "couldn't create manifest file requested at|{}|{}",
                manifest_file,
                why.description()
            ),
        };
        wherefile = Whereoutput::FilePointer(filepointer);
    }

    for x in 0..num_lines {
        message = rx.recv().unwrap();
        data = format!("{}", message.text);
        byte_count = byte_count + data.len();

        context.update(data.as_bytes());
        total_file_len = total_file_len + message.file_len;
        write_line(&mut wherefile, data);
        if x > SIGN_HEADER_MESSAGE_COUNT {
            if fileoutput {
                bar.inc(1);
            }
        }
    }
    let mut data = format!("{}\n", SEPARATOR);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());

    write_line(&mut wherefile, data);

    let duration = start.elapsed();
    data = format!("Time elapsed was|{:?}\n", duration);
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    data = format!(
        "Total number of files hashed is|{:?}\n",
        num_lines - SIGN_HEADER_MESSAGE_COUNT
    );
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    data = format!(
        "Total byte count of files in bytes is|{}\n",
        HumanBytes(total_file_len)
    );
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    data = format!(
        "Speed is|{}ps\n",
        HumanBytes((((total_file_len as f64) * 1000.0) / (duration.as_millis() as f64)) as u64)
    );
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    data = format!(
        "Average byte count per file in bytes is|{}\n",
        HumanBytes(
            ((total_file_len as f64) / ((num_lines - SIGN_HEADER_MESSAGE_COUNT) as f64)) as u64
        )
    );
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    let mut nonce_bytes: [u8; (NONCE_LENGTH_IN_BYTES / 8)] = [0; (NONCE_LENGTH_IN_BYTES / 8)];
    let mut rng = rand::thread_rng();
    let mut number: u8;
    for x in 0..(NONCE_LENGTH_IN_BYTES / 8) {
        number = rng.gen();
        nonce_bytes[x] = number;
    }
    data = format!("Nonce for file|{}\n", HEXUPPER.encode(&nonce_bytes));
    byte_count = byte_count + data.len();
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    data = format!("Sum of size of file so far is|{:?}\n", byte_count);
    context.update(data.as_bytes());
    write_line(&mut wherefile, data);

    let digest = context.finish();
    data = format!(
        "Hash of file so far|{}\n",
        HEXUPPER.encode(&digest.as_ref())
    );
    write_line(&mut wherefile, data);

    let signature = sign_data(&HEXUPPER.encode(&digest.as_ref()), private_key_bytes);
    data = format!(
        "Signature of hash|{}\n",
        HEXUPPER.encode(&signature.as_ref())
    );
    write_line(&mut wherefile, data);
    if fileoutput {
        bar.finish();
    }
}

pub fn parse_hash_manifest_line(line: String) -> &'static Algorithm {
    let tokens: Vec<&str> = line.split('|').collect();
    match tokens[1].as_ref() {
        "128" => {
            return &SHA1_FOR_LEGACY_USE_ONLY;
        }
        "256" => {
            return &SHA256;
        }
        "384" => {
            return &SHA384;
        }
        "512" => {
            return &SHA512;
        }
        "512_256" => {
            return &SHA512_256;
        }
        _ => {
            panic!("Hash line does not give a proper hash size.");
        }
    }
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
            "Couldn't open private key file named|{}|{}",
            private_key_file,
            why.description()
        ),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read private key file named|{}|{}",
            private_key_file,
            why.description()
        ),
    };
    let deserialized_map: BTreeMap<String, String> = match serde_yaml::from_str(&contents) {
        Ok(deserialized_map) => (deserialized_map),
        Err(why) => panic!(
            "Couldn't parse private key YAML file in|{}|{}",
            private_key_file,
            why.description()
        ),
    };
    let local_key = match HEXUPPER.decode(deserialized_map[PRIVATE_KEY_STRING_ED25519].as_bytes()) {
        Ok(local_key) => local_key,
        Err(why) => panic!(
            "Couldn't decode hex encoded private key|{}",
            why.description()
        ),
    };
    for x in 0..(PRIVATEKEY_LENGTH_IN_BYTES / 8) {
        private_key_bytes[x] = local_key[x];
    }
}

pub fn dump_header(header_file: &str) -> String {
    let mut file = match File::open(&header_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "Couldn't open header file named|{}|{}",
            header_file,
            why.description()
        ),
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read header file named|{}|{}",
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
            Err(why) => panic!("Couldn't load data from file to hash|{}", why.description()),
        };
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    context.finish()
}

pub fn check_line(
    path: String,
    hashalgo: &'static Algorithm,
    manifest_struct: ManifestLine,
    public_key_bytes: &[u8],
    check_tx: std::sync::mpsc::Sender<CheckMessage>,
) {
    let line_type: String;
    let path2 = path.clone();
    let path3 = path.clone();
    let path4 = path.clone();
    let data: String;
    let input: File;
    let digest_str: String;

    match fs::metadata(path) {
        Err(_why) => {
            data = format!(
                "{}|{}|{}|{}|{}|{}",
                "Bad-symlink", path2, 0, "00/00/0000 00:00:00", NO_HASH, manifest_struct.nonce
            );
        }
        Ok(metadata) => {
            let metadata2 = fs::symlink_metadata(path2).unwrap();
            let postfix : &str;
            if metadata2.file_type().is_symlink(){
                postfix = "-symlink"
            } else {
                postfix ="";
            }
            let filelen = format!("{}", metadata.len());
            send_pass_fail_check_message(
                filelen == manifest_struct.bytes,
                format!("{}|File length check passed.\n", path3),
                format!(
                    "{}|{}|{}|File len check failed.\n",
                    path3, manifest_struct.bytes, filelen
                ),
                &check_tx,
            );

            let datetime = match metadata.modified() {
                Err(why) => panic!(
                    "Couldn't load datetime from|{} data|{}",
                    path3,
                    why.description()
                ),
                Ok(datetime) => datetime,
            };
            let datetime: DateTime<Utc> = datetime.into();
            let datetime_string = format!("{}", datetime.format("%d/%m/%Y %T"));

            send_pass_fail_check_message(
                datetime_string == manifest_struct.time,
                format!("{}|Date check passed.\n", path3),
                format!(
                    "{}|{}|{}|File date check failed.\n",
                    path3, manifest_struct.time, datetime_string
                ),
                &check_tx,
            );

            if metadata.is_dir() {
                line_type =format!("Dir{}",postfix);
                digest_str = NO_HASH.to_string();
            } else {
                if metadata.is_file() {
                    line_type = format!("File{}",postfix);
                } else {
                    line_type = format!("Uknown{}",postfix);
                }
                input = match File::open(path3) {
                    Ok(input) => input,
                    Err(why) => panic!("Couldn't open file|{}|{}", path4, why.description()),
                };
                let reader = BufReader::new(input);
                let digest = var_digest(reader, hashalgo);
                digest_str = HEXUPPER.encode(&digest.as_ref());
            }
            send_pass_fail_check_message(
                line_type == manifest_struct.file_type,
                format!("{}|File type check passed.\n", path4),
                format!(
                    "{}|File type check failed|{}|{}\n",
                    path4, manifest_struct.file_type, line_type
                ),
                &check_tx,
            );

            send_pass_fail_check_message(
                digest_str == manifest_struct.hash,
                format!("{}|Hash check passed.\n", path4),
                format!(
                    "{}|Hash type check failed|{}|{}.\n",
                    path4, manifest_struct.hash, digest_str
                ),
                &check_tx,
            );

            data = format!(
                "{}|{}|{}|{}|{}|{}",
                manifest_struct.file_type,
                path4,
                manifest_struct.bytes,
                manifest_struct.time,
                manifest_struct.hash,
                manifest_struct.nonce
            );
        }
    };
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);

    let local_key = match HEXUPPER.decode(manifest_struct.sign.as_bytes()) {
        Ok(local_key) => (local_key),
        Err(why) => {
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "{}|Couldn't decode hex signature|{}\n",
                    path4,
                    why.description()
                ),
                false,
                &check_tx,
            );
            vec![0; SIGNED_LENGTH_IN_BYTES / 8]
        }
    };
    // figure this out don't dont want to crash
    let mut signature_key_bytes: [u8; (SIGNED_LENGTH_IN_BYTES / 8)] =
        [0; (SIGNED_LENGTH_IN_BYTES / 8)];

    for x in 0..SIGNED_LENGTH_IN_BYTES / 8 {
        signature_key_bytes[x] = local_key[x];
    }

    match public_key.verify(data.as_bytes(), &signature_key_bytes[..]) {
        Ok(_) => {
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "{}|Signature check passed. Can trust manifest line.\n",
                    path4
                ),
                true,
                &check_tx,
            );
        }
        Err(_) => {
            send_check_message(
                PRINT_MESSAGE,
                format!(
                    "{}|Signature check failed. Can't trust manifest line.\n",
                    path4
                ),
                false,
                &check_tx,
            );
        }
    };
    send_check_message(
        TICK_MESSAGE,
        "Tick".to_string(),
        false,
        &check_tx,
    );
}

pub fn create_line(
    path: String,
    hashalgo: &'static Algorithm,
    nonce_bytes: &[u8],
    private_key_bytes: &[u8],
    sign_tx: std::sync::mpsc::Sender<SignMessage>,
) {
    let line_type: String;
    let path2 = path.clone();
    let path3 = path.clone();
    let path4 = path.clone();
    let mut data: String;
    let mut filelen: u64 = 0;
    let signature: ring::signature::Signature;
    match fs::metadata(path) {
        Err(_why) => {
            data = format!(
                "{}|{}|{}|{}|{}|{}",
                "Bad-symlink",
                path2,
                filelen,
                "00/00/0000 00:00:00",
                NO_HASH,
                HEXUPPER.encode(&nonce_bytes)
            );
        }
        Ok(metadata) => {
            filelen = metadata.len();
            let datetime = match metadata.modified() {
                Err(why) => panic!(
                    "Couldn't load datetime from|{}|{}",
                    path3,
                    why.description()
                ),
                Ok(datetime) => datetime,
            };
            let metadata2 = fs::symlink_metadata(path2).unwrap();
            let postfix : &str;
            if metadata2.file_type().is_symlink(){
                postfix = "-symlink"
            } else {
                postfix ="";
            }
            let datetime: DateTime<Utc> = datetime.into();
            let input: File;
            let digest_str: String;
            if metadata.is_dir() {
                line_type = format!("Dir{}",postfix);
                digest_str = NO_HASH.to_string();
            } else if metadata.is_file() {
                input = match File::open(path3) {
                    Ok(input) => input,
                    Err(why) => panic!("Couldn't open file|{}|{}", path4, why.description()),
                };
                let reader = BufReader::new(input);
                let digest = var_digest(reader, hashalgo);
                digest_str = HEXUPPER.encode(&digest.as_ref());
                    line_type = format!("File{}",postfix);
                } else {
                    line_type = format!("Other{}",postfix);
                    digest_str = NO_HASH.to_string();
                }

            data = format!(
                "{}|{}|{}|{}|{}|{}",
                line_type,
                path4,
                filelen,
                datetime.format("%d/%m/%Y %T"),
                digest_str,
                HEXUPPER.encode(&nonce_bytes)
            );
        }
    };
    signature = sign_data(&data, &private_key_bytes);
    data = format!("{}|{}\n", data, HEXUPPER.encode(&signature.as_ref()));

    send_sign_message(data, filelen, &sign_tx);
}

pub fn create_keys(public_key_bytes: &mut [u8], private_key_bytes: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng) {
        Err(_) => panic!("Couldn't create pks8 key"),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
        Err(_) => panic!("Couldn't create key pair from pks8 key."),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    for x in 0..(PUBLICKEY_LENGTH_IN_BYTES / 8) {
        public_key_bytes[x] = key_pair.public_key().as_ref()[x];
    }
    for x in 0..(PRIVATEKEY_LENGTH_IN_BYTES / 8) {
        private_key_bytes[x] = pkcs8_bytes.as_ref()[x];
    }
}

pub fn write_key(public_key_bytes: &[u8], pubic_key_file: &str, key_name: &str) {
    let mut map = BTreeMap::new();
    map.insert(key_name.to_string(), HEXUPPER.encode(&public_key_bytes));
    let s = match serde_yaml::to_string(&map) {
        Ok(s) => s,
        Err(_) => panic!("Couldn't create YMAL string for|{}|key.", key_name),
    };
    let mut file = match File::create(&pubic_key_file) {
        Ok(file) => file,
        Err(why) => panic!(
            "couldn't create|{} key at|{}|{}",
            key_name,
            pubic_key_file,
            why.description()
        ),
    };
    match file.write_all(s.as_bytes()) {
        Ok(_) => (),
        Err(why) => panic!(
            "Couldn't write to|{} key to|{}|{}",
            key_name,
            pubic_key_file,
            why.description()
        ),
    };
}

pub fn read_public_key(public_key_file: &str, public_key_bytes: &mut [u8]) {
    let mut file = match File::open(public_key_file) {
        Ok(filepointer) => filepointer,
        Err(why) => panic!(
            "Couldn't find public key file requested at|{}|{}",
            public_key_file,
            why.description()
        ),
    };

    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't read from public key file requested at|{}|{}",
            public_key_file,
            why.description()
        ),
    };
    let deserialized_map: BTreeMap<String, String> = match serde_yaml::from_str(&contents) {
        Ok(deserialized_map) => (deserialized_map),
        Err(why) => panic!(
            "Couldn't parse public key from YAML file requested at|{}|{}",
            public_key_file,
            why.description()
        ),
    };
    let local_key = match HEXUPPER.decode(deserialized_map[PUBIC_KEY_STRING_ED25519].as_bytes()) {
        Ok(local_key) => (local_key),
        Err(why) => panic!(
            "Couldn't decode hex from public key file requested at|{}|{}",
            public_key_file,
            why.description()
        ),
    };
    for x in 0..PUBLICKEY_LENGTH_IN_BYTES / 8 {
        public_key_bytes[x] = local_key[x];
    }
}
pub fn write_keys(
    public_key_bytes: &[u8],
    private_key_bytes: &[u8],
    public_key_file: &str,
    private_key_file: &str,
) {
    write_key(&public_key_bytes, public_key_file, PUBIC_KEY_STRING_ED25519);
    write_key(
        &private_key_bytes,
        private_key_file,
        PRIVATE_KEY_STRING_ED25519,
    );
}

pub fn write_headers(
    sign_tx: &std::sync::mpsc::Sender<SignMessage>,
    inputhash: &str,
    command_line: &str,
    header_file: &str,
    now: &chrono::DateTime<Utc>,
    poolnumber: usize,
) {
    send_sign_message(format!("Manifest version|0.8.0\n").to_string(), 0, &sign_tx);
    send_sign_message(
        format!("Command Line|{}\n", &command_line).to_string(),
        0,
        &sign_tx,
    );
    send_sign_message(
        format!("Hash SHA|{}\n", &inputhash).to_string(),
        0,
        &sign_tx,
    );
    send_sign_message(
        format!("Signature algorthim|ED25519\n").to_string(),
        0,
        &sign_tx,
    );

    let data: String;
    if header_file == "|||" {
        data = "No header file requested for inclusion.\n".to_string();
    } else {
        data = dump_header(header_file);
    }
    send_sign_message(data, 0, &sign_tx);
    send_sign_message(format!("Start time was|{}\n", now.to_string()), 0, &sign_tx);
    send_sign_message(
        format!("Threads used for main hashing was|{}\n", poolnumber),
        0,
        &sign_tx,
    );
    send_sign_message(format!("{}\n", SEPARATOR), 0, &sign_tx);
}

pub fn read_manifest_file(vec_of_lines: &mut Vec<String>, input_file: &str, fileoutput: bool) {
    let f = match File::open(input_file) {
        Ok(f) => f,
        Err(why) => panic!(
            "Couldn't open manifest file for input at|{}|{}",
            input_file,
            why.description()
        ),
    };
    let spinner = ProgressBar::new_spinner();
    let file = BufReader::new(&f);
    if fileoutput {
        spinner.set_prefix("Parsing manifest took:");
        spinner.set_style(
            ProgressStyle::default_bar().template("{prefix} {elapsed_precise} {spinner}"),
        );
    }
    for line in file.lines() {
        if fileoutput {
            spinner.tick();
        }
        let l = line.unwrap();
        vec_of_lines.push(l);
    }
    if fileoutput {
        spinner.finish();
    }
}

pub fn get_next_manifest_line(
    mut manifest_line: String,
    vec_of_lines: &mut Vec<String>,
    context: &mut Context,
    file_len: &mut usize,
) -> String {
    manifest_line = manifest_line + "\n";
    context.update(manifest_line.as_bytes());
    *file_len = *file_len + manifest_line.len();
    return vec_of_lines.remove(0);
}

pub fn parse_next_manifest_line(
    manifest_line: &String,
    type_of_line: &mut String,
    file_name_line: &mut String,
    bytes_line: &mut String,
    time_line: &mut String,
    hash_line: &mut String,
    nonce_line: &mut String,
    sign_line: &mut String,
) {
    let tokens: Vec<&str> = manifest_line.split('|').collect();
    *type_of_line = tokens[0].to_string();
    *file_name_line = tokens[1].to_string();
    *bytes_line = tokens[2].to_string();
    *time_line = tokens[3].to_string();
    *hash_line = tokens[4].to_string();
    *nonce_line = tokens[5].to_string();
    *sign_line = tokens[6].to_string();
}

pub fn send_sign_message(
    message_string: String,
    len: u64,
    sign_tx: &std::sync::mpsc::Sender<SignMessage>,
) {
    let message = SignMessage {
        text: message_string.clone(),
        file_len: len,
    };
    match sign_tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send|{} to writing thread.|{}",
            message_string,
            why.description()
        ),
    };
}

pub fn send_check_message(
    message_type :u8,
    message_string: String,
    verbose: bool,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    let message = CheckMessage {
        check_type :message_type,
        text: message_string.clone(),
        verbose: verbose,
    };
    match check_tx.send(message) {
        Ok(_x) => (),
        Err(why) => panic!(
            "Couldn't send|{} to writing thread.|{}\n",
            message_string,
            why.description()
        ),
    };
}

pub fn send_pass_fail_check_message(
    pass_bool: bool,
    pass_string: String,
    fail_string: String,
    check_tx: &std::sync::mpsc::Sender<CheckMessage>,
) {
    if pass_bool {
        send_check_message(PRINT_MESSAGE,pass_string, true, check_tx)
    } else {
        send_check_message(PRINT_MESSAGE,fail_string, false, check_tx)
    }
}
