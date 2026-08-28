use bip39::{Language, Mnemonic};
use clap::{Arg, Command};
use pubky::{Keypair, recovery_file};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

fn is_valid_zbase32_char(c: char) -> bool {
    // z-base32 alphabet: ybndrfg8ejkmcpqxot1uwisza345h769
    matches!(
        c,
        'y' | 'b'
            | 'n'
            | 'd'
            | 'r'
            | 'f'
            | 'g'
            | '8'
            | 'e'
            | 'j'
            | 'k'
            | 'm'
            | 'c'
            | 'p'
            | 'q'
            | 'x'
            | 'o'
            | 't'
            | '1'
            | 'u'
            | 'w'
            | 'i'
            | 's'
            | 'z'
            | 'a'
            | '3'
            | '4'
            | '5'
            | 'h'
            | '7'
            | '6'
            | '9'
    )
}

pub fn get_secret_key_from_keypair(keypair: &Keypair) -> String {
    hex::encode(keypair.secret_key())
}

pub fn get_keypair_from_secret_key(secret_key: &str) -> Result<Keypair, String> {
    let bytes = match hex::decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Failed to decode secret key".to_string()),
    };

    let secret_key_bytes: [u8; 32] = match bytes.try_into() {
        Ok(secret_key) => secret_key,
        Err(_) => {
            return Err("Failed to convert secret key to 32-byte array".to_string());
        }
    };

    Ok(Keypair::from_secret_key(&secret_key_bytes))
}

fn get_keypair_from_mnemonic(mnemonic: &Mnemonic) -> Keypair {
    let seed = mnemonic.to_seed("");
    let secret_key: [u8; 32] = seed[..32]
        .try_into()
        .expect("a BIP39 seed always contains at least 32 bytes");

    Keypair::from_secret_key(&secret_key)
}

pub fn get_keypair_from_mnemonic_phrase(mnemonic_phrase: &str) -> Result<Keypair, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
        .map_err(|_| "Invalid mnemonic phrase".to_string())?;

    Ok(get_keypair_from_mnemonic(&mnemonic))
}

pub fn generate_mnemonic_and_keypair() -> Result<(String, Keypair), String> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)
        .map_err(|error| format!("Failed to generate mnemonic: {error}"))?;
    let keypair = get_keypair_from_mnemonic(&mnemonic);

    Ok((mnemonic.to_string(), keypair))
}

pub fn save_recovery_file(keypair: &Keypair, passphrase: &str) -> Vec<u8> {
    recovery_file::create_recovery_file(keypair, passphrase)
}

fn main() {
    // Parse command line arguments using clap
    let matches = Command::new("Vanity Pubky Generator")
        .version("1.0")
        .about("Generates public keys with a specified vanity prefix")
        .arg(
            Arg::new("vanity_name")
                .help("The desired vanity prefix for the public key")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .short('t')
                .help("Number of threads to use (defaults to CPU count)")
                .value_name("COUNT"),
        )
        .arg(
            Arg::new("passphrase")
                .long("passphrase")
                .short('p')
                .help("Passphrase for the recovery file (defaults to 'password')")
                .value_name("PASSPHRASE"),
        )
        .get_matches();

    // Get the required vanity name
    let raw_vanity_name = matches.get_one::<String>("vanity_name").unwrap();

    // Trim any leading or trailing spaces
    let trimmed_vanity_name = raw_vanity_name.trim();

    // Check if the trimmed string contains any spaces
    if trimmed_vanity_name.contains(' ') {
        eprintln!("Error: Vanity name cannot contain spaces.");
        std::process::exit(1);
    }

    // If the trimmed string is empty, exit with an error
    if trimmed_vanity_name.is_empty() {
        eprintln!("Error: Vanity name cannot be empty.");
        std::process::exit(1);
    }

    // Check if all characters in the vanity name are valid z-base32 characters
    let invalid_chars: Vec<char> = trimmed_vanity_name
        .chars()
        .filter(|&c| !is_valid_zbase32_char(c.to_ascii_lowercase()))
        .collect();

    if !invalid_chars.is_empty() {
        eprintln!(
            "Error: Vanity name contains invalid characters: {:?}",
            invalid_chars
        );
        eprintln!("Valid characters are: ybndrfg8ejkmcpqxot1uwisza345h769");
        eprintln!("Invalid characters that cannot be used: v0l2");
        std::process::exit(1);
    }

    // Convert to lowercase for case-insensitive matching
    let desired_prefix = trimmed_vanity_name.to_lowercase();

    // If the original string had spaces that were trimmed, inform the user
    if raw_vanity_name != trimmed_vanity_name {
        println!("Note: Leading/trailing spaces have been trimmed from the vanity name.");
    }

    // Get the optional number of threads with default as CPU count
    let num_threads = matches
        .get_one::<String>("threads")
        .map(|t| {
            t.parse::<usize>().unwrap_or_else(|_| {
                eprintln!("Warning: Invalid thread count, using CPU count instead");
                num_cpus::get()
            })
        })
        .unwrap_or_else(num_cpus::get);

    // Get the optional passphrase with default as "password"
    let has_passphrase = matches.contains_id("passphrase");
    let passphrase = matches
        .get_one::<String>("passphrase")
        .map(|s| s.as_str())
        .unwrap_or("password");

    println!("Generating public key with prefix: {}", desired_prefix);
    println!("Using {} threads", num_threads);
    println!(
        "Using passphrase: {}",
        if has_passphrase {
            "provided"
        } else {
            ": default"
        }
    );

    // Shared atomic counter for attempts
    let attempts = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();

    // Spawn worker threads
    let mut handles = vec![];
    for thread_id in 0..num_threads {
        let desired_prefix_clone = desired_prefix.clone();
        let attempts_clone = Arc::clone(&attempts);
        let found_clone = Arc::clone(&found);

        let handle = thread::spawn(move || {
            let thread_id = thread_id;
            let mut local_attempts = 0;

            while !found_clone.load(Ordering::Relaxed) {
                // Generate the keypair from a recovery phrase so Pubky Ring can import it.
                let (mnemonic, keypair) = generate_mnemonic_and_keypair()
                    .expect("generating a 12-word English mnemonic should not fail");
                let pubky = keypair.public_key();
                let pubky_str = pubky.to_string();

                // Convert to lowercase for case-insensitive comparison
                let lower_pubky = pubky_str.to_lowercase();

                local_attempts += 1;
                if local_attempts % 1000 == 0 {
                    attempts_clone.fetch_add(1000, Ordering::Relaxed);

                    // Print status update periodically from just one thread
                    if thread_id == 0 && local_attempts % 10000 == 0 {
                        let total = attempts_clone.load(Ordering::Relaxed);
                        println!("Still searching... {} attempts so far", total);
                    }
                }

                // Check if the public key starts with the desired prefix
                if lower_pubky.starts_with(&desired_prefix_clone) {
                    // Set the found flag to stop other threads
                    found_clone.store(true, Ordering::Relaxed);

                    // Get the secret key in hex format
                    let secret_key_hex = get_secret_key_from_keypair(&keypair);

                    // Return the found keys, recovery phrase, and keypair
                    return Some((pubky_str, secret_key_hex, mnemonic, keypair, local_attempts));
                }
            }

            // This thread didn't find a match
            None
        });

        handles.push(handle);
    }

    // Wait for results from threads
    let mut found_thread_attempts = 0;
    let mut result_pubkey = String::new();
    let mut result_secret_key = String::new();
    let mut result_mnemonic = String::new();
    let mut found_keypair: Option<Keypair> = None;

    for handle in handles {
        if let Ok(Some((pubky, secret_key, mnemonic, keypair, thread_attempts))) = handle.join() {
            result_pubkey = pubky;
            result_secret_key = secret_key;
            result_mnemonic = mnemonic;
            found_keypair = Some(keypair);
            found_thread_attempts = thread_attempts;
        }
    }

    // Calculate total attempts and time
    let total_attempts = attempts.load(Ordering::Relaxed) + found_thread_attempts;
    let elapsed = start_time.elapsed();

    if let Some(keypair) = found_keypair {
        println!(
            "Found matching public key after {} attempts and {:.2} seconds:",
            total_attempts,
            elapsed.as_secs_f64()
        );
        println!("Public key: {}", result_pubkey);
        println!("Private key: {}", result_secret_key);
        println!("Recovery phrase: {}", result_mnemonic);
        println!(
            "Average speed: {:.2} keys/second",
            total_attempts as f64 / elapsed.as_secs_f64()
        );

        // Create recovery file with provided or default passphrase
        let recovery_file_bytes = save_recovery_file(&keypair, passphrase);

        // Save the recovery file
        let filename = format!("{}_pubky_recovery.pkarr", desired_prefix);
        match File::create(&filename) {
            Ok(mut file) => match file.write_all(&recovery_file_bytes) {
                Ok(_) => println!(
                    "Recovery file saved: {} (with {})",
                    filename,
                    if has_passphrase {
                        "provided passphrase"
                    } else {
                        "default passphrase"
                    }
                ),
                Err(e) => println!("Failed to write recovery file: {}", e),
            },
            Err(e) => println!("Failed to create recovery file: {}", e),
        }
    } else {
        println!("No matching key found. This shouldn't happen!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZBASE32_ALPHABET: &str = "ybndrfg8ejkmcpqxot1uwisza345h769";

    fn deterministic_keypair() -> Keypair {
        let secret_key = std::array::from_fn(|index| index as u8);
        Keypair::from_secret_key(&secret_key)
    }

    #[test]
    fn accepts_exact_zbase32_alphabet() {
        for character in '!'..='~' {
            assert_eq!(
                is_valid_zbase32_char(character),
                ZBASE32_ALPHABET.contains(character),
                "unexpected validation result for {character:?}"
            );
        }
    }

    #[test]
    fn secret_key_is_lowercase_hex() {
        let secret_key = get_secret_key_from_keypair(&deterministic_keypair());

        assert_eq!(
            secret_key,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    }

    #[test]
    fn secret_key_round_trip_preserves_keypair() {
        let original = deterministic_keypair();
        let encoded = get_secret_key_from_keypair(&original);
        let decoded = get_keypair_from_secret_key(&encoded).expect("valid secret key");

        assert_eq!(decoded.secret_key(), original.secret_key());
        assert_eq!(decoded.public_key(), original.public_key());
    }

    #[test]
    fn secret_key_rejects_non_hex_input() {
        assert_eq!(
            get_keypair_from_secret_key("not-a-secret-key").unwrap_err(),
            "Failed to decode secret key"
        );
    }

    #[test]
    fn secret_key_rejects_incorrect_lengths() {
        for length in [31, 33] {
            let encoded = hex::encode(vec![0_u8; length]);
            assert_eq!(
                get_keypair_from_secret_key(&encoded).unwrap_err(),
                "Failed to convert secret key to 32-byte array"
            );
        }
    }

    #[test]
    fn pubky_ring_mnemonic_derivation_matches_known_vector() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keypair = get_keypair_from_mnemonic_phrase(mnemonic).expect("valid BIP39 mnemonic");

        assert_eq!(
            get_secret_key_from_keypair(&keypair),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        );
    }

    #[test]
    fn mnemonic_rejects_invalid_checksum() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        assert_eq!(
            get_keypair_from_mnemonic_phrase(mnemonic).unwrap_err(),
            "Invalid mnemonic phrase"
        );
    }

    #[test]
    fn generated_mnemonic_recovers_generated_keypair() {
        let (mnemonic, original) =
            generate_mnemonic_and_keypair().expect("mnemonic generation should succeed");
        let recovered =
            get_keypair_from_mnemonic_phrase(&mnemonic).expect("generated mnemonic should parse");

        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert_eq!(recovered.secret_key(), original.secret_key());
        assert_eq!(recovered.public_key(), original.public_key());
    }

    #[test]
    fn recovery_file_round_trip_preserves_keypair() {
        let original = deterministic_keypair();
        let recovery_file = save_recovery_file(&original, "correct horse battery staple");
        let recovered =
            recovery_file::decrypt_recovery_file(&recovery_file, "correct horse battery staple")
                .expect("recovery file should decrypt");

        assert!(recovery_file.starts_with(b"pubky.org/recovery\n"));
        assert_eq!(recovered.secret_key(), original.secret_key());
        assert_eq!(recovered.public_key(), original.public_key());
    }

    #[test]
    fn recovery_file_rejects_wrong_passphrase() {
        let recovery_file = save_recovery_file(&deterministic_keypair(), "right passphrase");

        assert!(recovery_file::decrypt_recovery_file(&recovery_file, "wrong passphrase").is_err());
    }
}
