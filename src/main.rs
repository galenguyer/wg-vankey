extern crate base64;
extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

fn main() {
    while true {
        match try_pair() {
             Some((pubkey, privkey)) => println!("public: {} private: {}", pubkey, privkey),
             None => {},
	}
    }
}

fn try_pair() -> Option<(String, String)> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public_key = base64::encode(keypair.public);

    return Some((public_key, base64::encode(keypair.secret)));
}
