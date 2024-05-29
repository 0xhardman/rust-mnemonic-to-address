use std::str::Bytes;

use bip39::{Language, Mnemonic, MnemonicType, Seed};

use bitcoin_hashes::{
    hex::{Case, DisplayHex},
    ripemd160, Hash,
};
use ring::{digest, hmac, rand};

// use secp256k1::hashes::{sha256, Hash};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

// use sha2::{Digest, Sha256};

fn step2_mnemonic_to_seed(mnemonic: &Mnemonic) -> String {
    // generate mnemonic
    let seed = Seed::new(mnemonic, "");
    seed.as_bytes();

    // let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    // let mnemonic: Mnemonic = Mnemonic::from_phrase(
    //     "indoor dish desk flag debris potato excuse depart ticket judge file exit",
    //     Language::English,
    // )
    // .unwrap();
    // let phrase = mnemonic.phrase();
    // println!("Generated Mnemonic: {}", phrase);
    hex::encode(seed.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step1_generate_mnemonic() {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(
            "indoor dish desk flag debris potato excuse depart ticket judge file exit",
            Language::English,
        )
        .unwrap();
        assert_eq!(step2_mnemonic_to_seed(&mnemonic), "3bd0bda567d4ea90f01e92d1921aacc5046128fd0e9bee96d070e1d606cb79225ee3e488bf6c898a857b5f980070d4d4ce9adf07d73458a271846ef3a8415320");
    }
}
