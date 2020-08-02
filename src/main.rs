extern crate base64;
extern crate ed25519_dalek;
extern crate rand;

use std::time::{Duration, SystemTime};
use clap::{App, Arg};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

fn main() {
    let matches = App::new("wg-vankey")
        .version("0.2.0")
        .author("Galen Guyer <galen@galenguyer.com>")
        .about("generate vanity wireguard public keys")
        .arg(
            Arg::with_name("PREFIX")
                .help("prefix to search for")
                .required(true)
                .index(1),
        )
        .get_matches();

    let prefix: &str = matches.value_of("PREFIX").unwrap();
    let time_for_one: u128 = time_one().as_nanos();
    println!("time for one attempt: {}", time_for_one);
    
    // TODO: Do this with exponents not multiplication loops (maybe)
    let mut est_attempts_per_key: u64 = 1;
    prefix.chars().for_each(|_| {
       est_attempts_per_key *= 64; 
    });
    println!("estimated attempts per key: {}", est_attempts_per_key);

    loop {
        if let Some((pubkey, privkey)) = try_pair(prefix) {
            println!("public: {} private: {}", pubkey, privkey)
        }
    }
}

fn try_pair(prefix: &str) -> Option<(String, String)> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public_key = base64::encode(keypair.public);
    if public_key.starts_with(prefix) {
        Some((public_key, base64::encode(keypair.secret)))
    } else {
        None
    }
}

fn time_one() -> Duration {
    let prefix: &str = "test";
    let iterations = 1000;
    let start_time = SystemTime::now();
    (0..iterations).for_each(|_| {
        try_pair(prefix);
    });
    start_time.elapsed().unwrap().checked_div(iterations).unwrap()
}