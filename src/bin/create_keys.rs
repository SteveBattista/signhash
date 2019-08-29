#![forbid(unsafe_code)]
use serde_yaml;
use std::collections::BTreeMap;
extern crate arrayref;
use data_encoding::HEXUPPER;
use ring::signature::KeyPair;
use std::fs::File;
use std::io::prelude::*;

fn create_keys(public_key_bytes: &mut [u8], private_key_bytes: &mut [u8]) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    for x in 0..32 {
        public_key_bytes[x] = key_pair.public_key().as_ref()[x];
    }
    for x in 0..85 {
        private_key_bytes[x] = pkcs8_bytes.as_ref()[x];
    }
}
fn write_pubic_key(public_key_bytes: &[u8]) {
    let mut map = BTreeMap::new();
    map.insert("Public".to_string(), HEXUPPER.encode(&public_key_bytes));
    let s = serde_yaml::to_string(&map).unwrap();
    //println!("{}", s);
    let mut file = File::create("Signpub.key").unwrap();
    file.write_all(s.as_bytes()).unwrap();
}

fn write_private_key(private_key_bytes: &[u8]) {
    let mut map = BTreeMap::new();
    map.insert("Private".to_string(), HEXUPPER.encode(&private_key_bytes));
    let s = serde_yaml::to_string(&map).unwrap();
    //println!("{}", s);
    let mut file = File::create("Signpriv.key").unwrap();
    file.write_all(s.as_bytes()).unwrap();
}

fn write_keys(public_key_bytes: &[u8], private_key_bytes: &[u8]) {
    write_pubic_key(&public_key_bytes);
    write_private_key(&private_key_bytes)
}
/*fn read_private_key(private_key_bytes :  & mut [u8]){
    let mut file = File::open("Signpriv.key").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized_map: BTreeMap<String, String> = serde_yaml::from_str(&contents).unwrap();
    //println!("{}",deserialized_map["Private"]);
    let  local_key = HEXUPPER.decode(deserialized_map["Private"].as_bytes()).unwrap();
    for x in 0..85 {
        private_key_bytes[x] = local_key[x];
    }
}

fn read_public_key(public_key_bytes :  & mut [u8]){
    let mut file = File::open("Signpub.key").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let deserialized_map: BTreeMap<String, String> = serde_yaml::from_str(&contents).unwrap();
    //println!("{}",deserialized_map["Public"]);
    let  local_key = HEXUPPER.decode(deserialized_map["Public"].as_bytes()).unwrap();
    for x in 0..32 {
        public_key_bytes[x] = local_key[x];
    }
}
*/

fn main() {
    let mut public_key_bytes: [u8; 32] = [0; 32];
    let mut private_key_bytes: [u8; 85] = [0; 85];
    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    println!("Public : {}", HEXUPPER.encode(&public_key_bytes));
    println!("Private : {}", HEXUPPER.encode(&private_key_bytes));
    write_keys(&public_key_bytes, &private_key_bytes);
    /*let mut public_key_bytes2: [u8;32]=[0;32];
    let mut private_key_bytes2 :  [u8;85]= [0;85];
    read_private_key(& mut private_key_bytes2);
    read_public_key(& mut public_key_bytes2);
    println!("Public : {}", HEXUPPER.encode(&public_key_bytes2));
    println!("Private : {}", HEXUPPER.encode(&private_key_bytes2));
    assert_eq!(HEXUPPER.encode(&public_key_bytes),HEXUPPER.encode(&public_key_bytes2));
    assert_eq!(HEXUPPER.encode(&private_key_bytes),HEXUPPER.encode(&private_key_bytes2)); */
}
