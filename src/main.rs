extern crate base64;
extern crate ed25519_dalek;
extern crate rand;

use clap::{App, Arg};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

fn main() {
    let matches = App::new("wg-vankey")
        .version("0.1.0")
        .author("Galen Guyer <galen@galenguyer.com>")
        .about("generate vanity wireguard public keys")
        .get_matches();

    while true {
        match try_pair("ava") {
            Some((pubkey, privkey)) => println!("public: {} private: {}", pubkey, privkey),
            None => {}
        }
    }
}

fn try_pair(prefix: &str) -> Option<(String, String)> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public_key = base64::encode(keypair.public);
    if public_key.starts_with(prefix) {
        return Some((public_key, base64::encode(keypair.secret)));
    } else {
        return None;
    }
}
