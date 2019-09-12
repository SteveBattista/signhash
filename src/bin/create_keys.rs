#![forbid(unsafe_code)]
use std::error::Error;
use serde_yaml;
use std::collections::BTreeMap;
//extern crate arrayref;
use data_encoding::HEXUPPER;
use ring::signature::KeyPair;
use std::fs::File;
use std::io::prelude::*;
use clap::{App, Arg};

const PRIVATEKEY_LENGH_IN_BYTES: usize = 680;
const PUBLICKEY_LENGH_IN_BYTES:usize = 256;

fn create_keys(public_key_bytes: &mut [u8], private_key_bytes: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng){
        Err(_) => panic!("Couldn't create pks8 key"),
        Ok(pkcs8_bytes) => pkcs8_bytes,
        };


    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()){
        Err(_) => panic!("Couldn't create keypair from pks8 key."),
        Ok(pkcs8_bytes) => pkcs8_bytes,
    };

    for x in 0..(PUBLICKEY_LENGH_IN_BYTES/8) {
        public_key_bytes[x] = key_pair.public_key().as_ref()[x];
    }
    for x in 0..(PRIVATEKEY_LENGH_IN_BYTES/8) {
        private_key_bytes[x] = pkcs8_bytes.as_ref()[x];
    }
}

fn write_key(public_key_bytes: &[u8], pubic_key_file: &str, key_name: &str) {
    let mut map = BTreeMap::new();
    map.insert(key_name.to_string(), HEXUPPER.encode(&public_key_bytes));
    let s = match serde_yaml::to_string(&map) {
        Err(_) => panic!("Couldn't create YMAL string for {} key.",key_name),
        Ok(s) => s,
    };
    let mut file = match File::create(&pubic_key_file){
        Err(why) => panic!("couldn't create {} key at {}: {}", key_name, pubic_key_file, why.description()),
        Ok(file) => file,
    };
    match file.write_all(s.as_bytes()) {
        Err(why) => panic!("Couldn't write to {} key to {}: {}", key_name, pubic_key_file, why.description()),
        Ok(_) => println!("Successfully wrote {} key to {}", key_name, pubic_key_file),
    }
}

fn write_keys(public_key_bytes: &[u8], private_key_bytes: &[u8], public_key_file: &str, private_key_file: &str) {
    write_key(&public_key_bytes, public_key_file,"Public");
    write_key(&private_key_bytes,private_key_file,"Private");
}

fn main() {
    let matches = App::new("Create Keys")
                          .version("1.0")
                          .author("Stephen Battista <stephen.battista@gmail.com>")
                          .about("Creates the private and public keys for a 25519 ecliptic curve keys.")
                          .arg(Arg::with_name("private")
                              .short("i")
                               .long("private")
                               .value_name("FILE")
                               .help("This option allows for the user to set the location of the private key. I would reccomend placing it in a location where others can not read it. If not used, Signpriv.key is default. ")
                               .takes_value(true))
                         .arg(Arg::with_name("public")
                                   .short("u")
                                    .long("public")
                                    .value_name("FILE")
                                    .help("This option allows for the user to set the location of the public key. If not used, Signpub.key is default.")
                                    .takes_value(true))
                          .get_matches();
    let private_filename = matches.value_of("private").unwrap_or("Signpriv.key");
    let pubic_filename = matches.value_of("public").unwrap_or("Signpub.key");
    let mut public_key_bytes: [u8; (PUBLICKEY_LENGH_IN_BYTES/8)] = [0; (PUBLICKEY_LENGH_IN_BYTES/8)];
    let mut private_key_bytes: [u8; (PRIVATEKEY_LENGH_IN_BYTES/8)] = [0; (PRIVATEKEY_LENGH_IN_BYTES/8)];
    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    write_keys(&public_key_bytes, &private_key_bytes,pubic_filename,private_filename);

}
