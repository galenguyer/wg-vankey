extern crate base64;
extern crate ed25519_dalek;
extern crate rand;

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

    loop {
        if let Some((pubkey, privkey)) = try_pair(matches.value_of("PREFIX").unwrap()) {
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
