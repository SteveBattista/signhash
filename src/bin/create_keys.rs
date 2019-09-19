#![forbid(unsafe_code)]

//extern crate arrayref;
use clap::{App, Arg};
use signhash::create_keys;
use signhash::write_keys;

const PRIVATEKEY_LENGH_IN_BYTES: usize = 680;
const PUBLICKEY_LENGH_IN_BYTES: usize = 256;


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
    let mut public_key_bytes: [u8; (PUBLICKEY_LENGH_IN_BYTES / 8)] =
        [0; (PUBLICKEY_LENGH_IN_BYTES / 8)];
    let mut private_key_bytes: [u8; (PRIVATEKEY_LENGH_IN_BYTES / 8)] =
        [0; (PRIVATEKEY_LENGH_IN_BYTES / 8)];
    create_keys(&mut public_key_bytes, &mut private_key_bytes);
    write_keys(
        &public_key_bytes,
        &private_key_bytes,
        pubic_filename,
        private_filename,
    );
}
