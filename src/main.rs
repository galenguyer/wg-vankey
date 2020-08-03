use clap::{App, Arg};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::thread;
use std::time::{Duration, SystemTime};

fn main() {
    let matches = App::new("wg-vankey")
        .version("0.2.0")
        .author("Galen Guyer <galen@galenguyer.com>")
        .about("generate vanity wireguard public keys")
        .arg(
            Arg::with_name("PREFIX")
                .help("prefix to search for")
                .required(true),
        )
        .arg(
            Arg::with_name("core-count")
                .long("core-count")
                .short("c")
.takes_value(true)
                .help(
                "specify the number of cpu cores to use. defaults to all cores if not specified",
            ),
        )
        .get_matches();

    let prefix: &str = matches.value_of("PREFIX").unwrap();
    let core_count: usize = match matches.value_of("core-count") {
        Some(val) => usize::from_str_radix(val, 10).unwrap().min(num_cpus::get()),
        None => num_cpus::get(),
    };

    println!("{} cores available, using {}", num_cpus::get(), core_count);

    let time_for_one: u128 = time_one().as_nanos();
    println!("time for one attempt: {}", format_ns(time_for_one as u64));

    // TODO: Do this with exponents not multiplication loops (maybe)
    let mut est_attempts_per_key: u64 = 1;
    prefix.chars().for_each(|_| {
        est_attempts_per_key *= 64;
    });
    println!("estimated attempts per key: {}", est_attempts_per_key);

    println!(
        "estimated time per key: {}",
        format_ns(time_for_one as u64 * est_attempts_per_key)
    );
    println!("press ctrl+c to cancel at any time");

    thread::sleep(Duration::from_secs(2));
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
    start_time
        .elapsed()
        .unwrap()
        .checked_div(iterations)
        .unwrap()
}

fn format_ns(nanos: u64) -> String {
    if nanos < 1000 {
        return format!("{}ns", nanos);
    } else if nanos < (1000 * 1000) {
        return format!("{}us", (nanos / 1000));
    } else if nanos < (1000 * 1000 * 1000) {
        return format!("{}ms", (nanos / (1000 * 1000)));
    } else if nanos < (60 * 1000 * 1000 * 1000) {
        return format!("{}s", (nanos / (1000 * 1000 * 1000)));
    } else if nanos < (60 * 60 * 1000 * 1000 * 1000) {
        return format!("{}m", (nanos / (60 * 1000 * 1000 * 1000)));
    }
    return format!("{}h", (nanos / (60 * 60 * 1000 * 1000 * 1000)));
}
