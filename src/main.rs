extern crate base64;
extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::{Keypair, PublicKey};
use rand::rngs::OsRng;

fn main() {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public_key: PublicKey = keypair.public;
    println!("{}", base64::encode(public_key));
}
