use base64::Engine;
use base64::engine::general_purpose as bs64;
use clap::{App, Arg};
use rand_core::OsRng;
use regex::{Regex, RegexBuilder};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret as SecretKey;

fn main() {
    let matches = App::new("wg-vankey")
        .version("2.0.0")
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
	.arg(
            Arg::with_name("regex")
		.long("regex")
		.short("r")
		.takes_value(false)
		.help("treat the input as regex instead of a plain string"),
	    )
        .get_matches();

    // the prefix has to be a static str in order to ensure it lives long enough for future threads
    // to consume it
    let prefix: &'static str = string_to_static_str(matches.value_of("PREFIX").unwrap().to_owned());
    let ignore_case: bool = matches.is_present("ignore-case");
    let use_regex: bool = matches.is_present("regex");
    // set the core count to either the count given or the number of available cores
    let core_count: usize = match matches.value_of("core-count") {
        Some(val) => val.parse::<usize>().unwrap().min(num_cpus::get()),
        None => num_cpus::get(),
    };
    println!("{} cores available, using {}", num_cpus::get(), core_count);

    // estimate how long a single key generation takes for time estimation later
    let time_for_one: Duration = time_one(use_regex);
    println!(
        "time for one attempt: {:?} ({} keys/second)",
        time_for_one,
        ((core_count as f64) / time_for_one.as_secs_f64()).round()
    );

    if !use_regex {
        // estimate how many attempts each key will take
        let mut est_attempts_per_key: u32 = 1;
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
            "estimated time per key: {:?}",
            time_for_one
                .checked_mul(est_attempts_per_key)
                .unwrap()
                .checked_div(core_count as u32)
                .unwrap()
        );
    }
    println!("press ctrl+c to cancel at any time");

    // wait two seconds to give the user a chance to cancel if they did an accidentally quick key
    thread::sleep(Duration::from_secs(2));

    let mut threads = Vec::new();
    if use_regex {
        let key_regex: Regex = RegexBuilder::new(prefix)
            .case_insensitive(ignore_case)
            .build()
            .unwrap();
        let arc_regex = Arc::new(key_regex);
        for _ in 0..core_count {
            let arc_regex = Arc::clone(&arc_regex);
            threads.push(std::thread::spawn(move || loop {
                if let Some((pubkey, privkey)) = try_regex(&arc_regex) {
                    println!(
                        "{}: public: {} private: {}",
                        chrono::Utc::now().format("%T%.3f").to_string(),
                        pubkey,
                        privkey
                    )
                }
            }));
        }
    } else {
        for _ in 0..core_count {
            threads.push(std::thread::spawn(move || loop {
                if let Some((pubkey, privkey)) = try_pair(prefix, ignore_case) {
                    println!("public: {} private: {}", pubkey, privkey)
                }
            }));
        }
    }

    // In theory, you should only need to join one of the threads, but this is more robust.
    for thread in threads {
        thread.join().expect("thread panicked with error")
    }
}

fn try_pair(prefix: &'static str, ignore_case: bool) -> Option<(String, String)> {
    // generate a key pair but don't encode the private key yet in order to save time
    let private_key: SecretKey = SecretKey::new(OsRng);
    let public_key = bs64::STANDARD.encode(PublicKey::from(&private_key).to_bytes());
    // if the public key starts with the prefix OR if ignore_case is set and a case-insensitive match
    // is made, return the public key and encoded private key
    if public_key.starts_with(prefix)
        || (ignore_case
            && public_key
                .to_uppercase()
                .starts_with(prefix.to_uppercase().as_str()))
    {
        Some((public_key, bs64::STANDARD.encode(private_key.to_bytes())))
    } else {
        None
    }
}

fn try_regex(prefix: &Arc<Regex>) -> Option<(String, String)> {
    // generate a key pair but don't encode the private key yet in order to save time
    let private_key: SecretKey = SecretKey::new(OsRng);
    let public_key = bs64::STANDARD.encode(PublicKey::from(&private_key).to_bytes());
    // if the public key starts with the prefix OR if ignore_case is set and a case-insensitive match
    // is made, return the public key and encoded private key
    if prefix.is_match(&public_key) {
        Some((public_key, bs64::STANDARD.encode(private_key.to_bytes())))
    } else {
        None
    }
}

// run 1,000 iterations of key generation to get a good average of how long each key takes to generate
fn time_one(use_regex: bool) -> Duration {
    let prefix = string_to_static_str(String::from("test"));
    let iterations = 1000;
    let start_time = Instant::now();
    if use_regex {
        let t_regex: Arc<Regex> = Arc::new(Regex::new("t[o|0]ast").unwrap());
        (0..iterations).for_each(|_| {
            try_regex(&t_regex);
        });
    } else {
        (0..iterations).for_each(|_| {
            try_pair(prefix, false);
        });
    }
    start_time.elapsed().checked_div(iterations).unwrap()
}

// needed for ensuring the prefix has a long enough lifetime
fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
