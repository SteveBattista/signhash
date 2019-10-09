#![forbid(unsafe_code)]

use signhash::get_next_manifest_line;
use signhash::parse_hash_manifest_line;
use signhash::parse_next_manifest_line;
use signhash::read_manifest_file;
use signhash::read_public_key;
use signhash::write_line;
use signhash::Whereoutput;
use signhash::DEFAULT_MANIFEST_FILE_NAME;
use signhash::DEFAULT_PUBIC_KEY_FILE_NAME;
use signhash::PUBLICKEY_LENGTH_IN_BYTES;
use signhash::SEPERATOR;
use signhash::SIGNED_LENGH_IN_BYTES;
use std::convert::TryInto;
use std::fs::File;

use clap::{App, Arg};

use ring::digest::Context;

use std::error::Error;

use data_encoding::HEXUPPER;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

const NUMBER_OF_LINES_UNTIL_FILE_LEN_MESSAGE: usize = 7;
const NUMBER_OF_LINES_AFTER_FILES: usize = 10;
const NO_OUTPUTFILE: &'static str = "|||";

fn main() {
    let matches = App::new("check_manifest")
    .version("0.1.0")
    .author("Stephen Battista <stephen.battista@gmail.com>")
    .about("Checks the integitry of manfest file by checking each signature, the file lengh, hash and signature of the the manifest")
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
    .get_matches();

    let mut public_key_bytes: [u8; (PUBLICKEY_LENGTH_IN_BYTES / 8)] =
        [0; (PUBLICKEY_LENGTH_IN_BYTES / 8)];
    let public_key_file = matches
        .value_of("public")
        .unwrap_or(DEFAULT_PUBIC_KEY_FILE_NAME);
    read_public_key(public_key_file, &mut public_key_bytes);

    let output_file = matches
        .value_of("output")
        .unwrap_or(NO_OUTPUTFILE)
        .to_string();

    let mut fileoutput = true;
    if output_file == NO_OUTPUTFILE {
        fileoutput = false;
    }

    let mut wherefile: Whereoutput;
    let filepointer: File;
    if !fileoutput {
        wherefile = Whereoutput::StringText("STDIO".to_owned());
    } else {
        filepointer = match File::create(&output_file) {
            Ok(filepointer) => filepointer,
            Err(why) => panic!(
                "couldn't create check file requested at {}: {}",
                output_file,
                why.description()
            ),
        };
        wherefile = Whereoutput::FilePointer(filepointer);
    }

    let input_file = matches
        .value_of("input")
        .unwrap_or(DEFAULT_MANIFEST_FILE_NAME)
        .to_string();

    let mut vec_of_lines: Vec<String> = Vec::new();
    read_manifest_file(&mut vec_of_lines, &input_file, fileoutput);

    let mut version_line = vec_of_lines.remove(0);
    let mut command_line = vec_of_lines.remove(0);
    let mut hash_line = vec_of_lines.remove(0);

    let hashalgo = parse_hash_manifest_line(hash_line.clone());

    let mut file_hash_context = Context::new(hashalgo);

    let mut file_len: usize = 0;

    version_line = version_line + "\n";
    file_hash_context.update(version_line.as_bytes());
    file_len = file_len + version_line.len();

    command_line = command_line + "\n";
    file_hash_context.update(command_line.as_bytes());
    file_len = file_len + command_line.len();

    hash_line = hash_line + "\n";
    file_hash_context.update(hash_line.as_bytes());
    file_len = file_len + hash_line.len();

    let mut manifest_line = vec_of_lines.remove(0);

    while manifest_line != SEPERATOR {
        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
    }

    let bar = ProgressBar::new(
        (vec_of_lines.len() - NUMBER_OF_LINES_AFTER_FILES)
            .try_into()
            .unwrap(),
    );
    if fileoutput {
        bar.set_prefix("Number of lines checked:");
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {wide_bar} {pos}/{len} {elapsed_precise}"),
        );
    }
    let mut type_of_line = String::new();
    let mut file_name_line = String::new();
    let mut bytes_line = String::new();
    let mut time_line = String::new();
    let mut nonce_line = String::new();
    let mut hash_line = String::new();
    let mut sign_line = String::new();

    manifest_line = get_next_manifest_line(
        manifest_line,
        &mut vec_of_lines,
        &mut file_hash_context,
        &mut file_len,
    );

    while manifest_line != SEPERATOR {
        parse_next_manifest_line(
            &manifest_line,
            &mut type_of_line,
            &mut file_name_line,
            &mut bytes_line,
            &mut time_line,
            &mut hash_line,
            &mut nonce_line,
            &mut sign_line,
        );

        let mut data = format!(
            "{}|{}|{}|{}|{}|{}",
            type_of_line, file_name_line, bytes_line, time_line, hash_line, nonce_line
        );

        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);

        let local_key = match HEXUPPER.decode(sign_line.as_bytes()) {
            Ok(local_key) => (local_key),
            Err(why) => {
                data = format!(
                    "{}|Couldn't decode hex signature|{}\n",
                    file_name_line,
                    why.description()
                );
                write_line(&mut wherefile, data.clone());
                vec![0; SIGNED_LENGH_IN_BYTES / 8]
            }
        };
        // figure this out don't dont want to crash
        let mut signature_key_bytes: [u8; (SIGNED_LENGH_IN_BYTES / 8)] =
            [0; (SIGNED_LENGH_IN_BYTES / 8)];

        for x in 0..SIGNED_LENGH_IN_BYTES / 8 {
            signature_key_bytes[x] = local_key[x];
        }

        match public_key.verify(data.as_bytes(), &signature_key_bytes[..]) {
            Ok(_) => (),
            Err(_) => {
                data = format!(
                    "{}|Signature check failed. Can't trust manifest line.\n",
                    file_name_line
                );
                write_line(&mut wherefile, data);
            }
        };

        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
        if fileoutput {
            bar.inc(1);
        }
    }
    if fileoutput {
        bar.finish();
    }
    for _x in 0..NUMBER_OF_LINES_UNTIL_FILE_LEN_MESSAGE {
        manifest_line = get_next_manifest_line(
            manifest_line,
            &mut vec_of_lines,
            &mut file_hash_context,
            &mut file_len,
        );
    }

    let mut manifest_line2 = manifest_line.clone();

    manifest_line2 = manifest_line2 + "\n";
    file_hash_context.update(manifest_line2.as_bytes());

    let tokens: Vec<&str> = manifest_line.split('|').collect();
    let data: String;
    if tokens[1] == format!("{}", file_len) {
        data = format!("File lengh of manifest is corect.\n");
        write_line(&mut wherefile, data);
    } else {
        data = format!(
            "File lengh was reported in manifest as {}. Observed length of manifest is {}.\n",
            tokens[1], file_len
        );
        write_line(&mut wherefile, data);
    }

    let digest = file_hash_context.finish();
    let digest_text = HEXUPPER.encode(&digest.as_ref());
    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split('|').collect();
    let mut data: String;
    if tokens[1] == digest_text {
        data = format!("Manifest digest is correct.\n");
        write_line(&mut wherefile, data);
    } else {
        data = format!(
            "Hash was reported as {} in manifest. Observed hash is {}.\n",
            tokens[1], digest_text
        );
        write_line(&mut wherefile, data);
    }

    manifest_line = vec_of_lines.remove(0);
    let tokens: Vec<&str> = manifest_line.split('|').collect();

    let local_key = match HEXUPPER.decode(tokens[1].as_bytes()) {
        Ok(local_key) => (local_key),
        Err(why) => {
            data = format!(
                "Couldn't decode hex signature for manifest file|{}.\n",
                why.description()
            );
            write_line(&mut wherefile, data);
            vec![0; SIGNED_LENGH_IN_BYTES / 8]
        }
    };
    // figure this out don't dont want to crash
    let mut signature_key_bytes: [u8; (SIGNED_LENGH_IN_BYTES / 8)] =
        [0; (SIGNED_LENGH_IN_BYTES / 8)];

    for x in 0..SIGNED_LENGH_IN_BYTES / 8 {
        signature_key_bytes[x] = local_key[x];
    }
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key_bytes);
    let data: String;
    match public_key.verify(digest_text.as_bytes(), &signature_key_bytes[..]) {
        Ok(_x) => {
            data = format!("Signature of manifest is correct.\n");
            write_line(&mut wherefile, data);
        }
        Err(_) => {
            data = format!("Signature of manifest did not match the hash in the manifest.\n");
            write_line(&mut wherefile, data);
        }
    };
}
