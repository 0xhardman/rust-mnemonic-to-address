use std::str::Bytes;

use bip39::{Language, Mnemonic, Seed};

// use sha2::{Digest, Sha256};

fn step2_mnemonic_to_seed(mnemonic: &Mnemonic) -> String {
    let seed = Seed::new(mnemonic, "");
    seed.as_bytes();
    hex::encode(seed.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        // # Step 2 - Mnemonic to Seed
        // To convert a mnemonic to a seed, we need to use the PBKDF2 function with the mnemonic as the password and the string "mnemonic" + passphrase as the salt.
        // The main function of PBKDF2 is to convert a password into an encryption key. Unlike traditional one-shot hash functions, PBKDF2 generates the key by combining the password with a salt (Salt) and repeatedly applying the hash function several times.
        // Normally, the number of iterations is set to 2048 and HMAC-SHA512 is used as the hash function to make it difficult to brute force the seed.
        // So the length of the seed is 512 bits (64 bytes).
        let mnemonic: Mnemonic = Mnemonic::from_phrase(
            "indoor dish desk flag debris potato excuse depart ticket judge file exit",
            Language::English,
        )
        .unwrap();
        assert_eq!(step2_mnemonic_to_seed(&mnemonic), "3bd0bda567d4ea90f01e92d1921aacc5046128fd0e9bee96d070e1d606cb79225ee3e488bf6c898a857b5f980070d4d4ce9adf07d73458a271846ef3a8415320");
    }
}
