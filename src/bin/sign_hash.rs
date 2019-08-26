#![forbid(unsafe_code)]
use std::io::Write;
use clap::{App, Arg};
use data_encoding::HEXUPPER;
use ring::digest::{Context, SHA256, SHA384, SHA512,Algorithm,Digest};
use scoped_threadpool::Pool;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};
use std::process::exit;
use std::collections::BTreeMap;

fn main() {
    let matches = App::new("sign_hash")
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
    match inputhash.as_ref() {
        "256" => hashalgo = &SHA256,
        "384" => hashalgo = &SHA384,
        "512" => hashalgo = &SHA512,
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
    //    println!("pool chosen is {}", inputpool);

    let inputfiles: Vec<_> = matches.values_of("files").unwrap().collect();
    //   println!("Files chosen is {}", inputpool.len());
    let inputfiles = inputfiles.into_iter().filter(|&file| !(file.ends_with(".sig")) ).collect::<Vec<_>>();

    pool.scoped(|scoped| {
        for file in inputfiles {
            scoped.execute(move || {
                let _x = gethashofile(&file, hashalgo);
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
fn write_hash(hash: &[u8],path: &str){
    let mut map = BTreeMap::new();
    map.insert("HASH".to_string(), HEXUPPER.encode(&hash));
    let s = serde_yaml::to_string(&map).unwrap();
    //println!("{}", s);
    let new_path = path.to_owned() + ".sig";
    //println!("{}",new_path);
    let mut file = File::create(new_path).unwrap();
    file.write_all(s.as_bytes()).unwrap();
}

fn gethashofile(path: &str, hashalgo: &'static Algorithm) -> Result<(), Box<dyn Error>> {
    let input = File::open(path)?;
    let reader = BufReader::new(input);
    let digest = var_digest(reader, hashalgo)?;
    write_hash(& digest.as_ref(), path);
//    println!("{} : {}", path, HEXUPPER.encode(digest.as_ref()));
    Ok(())
}
