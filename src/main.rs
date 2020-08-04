use clap::{App, Arg};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use std::thread;
use std::time::{Duration, SystemTime};
use threadpool::ThreadPool;

fn main() {
    let matches = App::new("wg-vankey")
        .version("1.0.3")
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
                "specify the number of cpu cores to use.\ndefaults to all cores if not specified",
            ),
        )
	.arg(Arg::with_name("ignore-case").long("ignore-case").short("i").takes_value(false).help("ignore case matching"))
        .get_matches();

    // the prefix has to be a static str in order to ensure it lives long enough for future threads
    // to consume it
    let prefix: &'static str = string_to_static_str(matches.value_of("PREFIX").unwrap().to_owned());
    let ignore_case: bool = matches.is_present("ignore-case");
    // set the core count to either the count given or the number of available cores 
    let core_count: usize = match matches.value_of("core-count") {
        Some(val) => usize::from_str_radix(val, 10).unwrap().min(num_cpus::get()),
        None => num_cpus::get(),
    };
    println!("{} cores available, using {}", num_cpus::get(), core_count);

    // estimate how long a single key generation takes for time estimation later
    let time_for_one: u128 = time_one().as_nanos();
    println!(
        "time for one attempt: {} ({} keys/second)",
        format_ns(time_for_one as u64),
        (1000000000 * core_count / (time_for_one as usize))
    );

    // estimate how many attempts each key will take 
    let mut est_attempts_per_key: u64 = 1;
    prefix.chars().for_each(|c| {
        // each additional character given increases the needed guesses by 64-fold
        est_attempts_per_key *= 64;
        // if ignore_case is set, each letter has two valid options, halving the needed attempts
        if ignore_case && c.is_ascii_alphabetic() {
            est_attempts_per_key /= 2;
        }
    });
    println!("estimated attempts per key: {}", est_attempts_per_key);

    // estimate time per key using the time for a single key, the number of cores
    // to use, and how many attempts each key is estimated to take
    println!(
        "estimated time per key: {}",
        format_ns((time_for_one / (core_count as u128)) as u64 * est_attempts_per_key)
    );
    println!("press ctrl+c to cancel at any time");

    // wait two seconds to give the user a chance to cancel if they did an accidentally quick key
    thread::sleep(Duration::from_secs(2));

    // TODO: this seems to create a pool with one more thread than specified
    let pool = ThreadPool::new(core_count);
    loop {
        pool.execute(move || {
            if let Some((pubkey, privkey)) = try_pair(prefix, ignore_case) {
                println!("public: {} private: {}", pubkey, privkey)
            }
        });
    }
}

fn try_pair(prefix: &'static str, ignore_case: bool) -> Option<(String, String)> {
    // generate a key pair but don't encode the private key yet in order to save time
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public_key = base64::encode(keypair.public);
    // if the public key starts with the prefix OR if ignore_case is set and a case-insensitive match
    // is made, return the public key and encoded private key
    if public_key.starts_with(prefix)
        || (ignore_case
            && public_key
                .to_uppercase()
                .starts_with(prefix.to_uppercase().as_str()))
    {
        Some((public_key, base64::encode(keypair.secret)))
    } else {
        None
    }
}

// run 10,000 iterations of key generation to get a good average of how long each key takes to generate
fn time_one() -> Duration {
    let prefix = string_to_static_str(String::from("test"));
    let iterations = 10000;
    let start_time = SystemTime::now();
    (0..iterations).for_each(|_| {
        try_pair(prefix, false);
    });
    start_time
        .elapsed()
        .unwrap()
        .checked_div(iterations)
        .unwrap()
}

// TODO: cursed_code
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

// needed for ensuring the prefix has a long enough lifetime
fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
