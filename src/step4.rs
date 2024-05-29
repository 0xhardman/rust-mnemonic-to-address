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

use crate::utils::derive_with_path;

// use sha2::{Digest, Sha256};

fn step3_master_kay_to_private_key(
    master_secret_key_hex: String,
    master_chain_code_hex: String,
    derived_path: [u32; 5],
) -> String {
    let master_secret_key_vec = hex::decode(master_secret_key_hex).unwrap();
    let master_secret_key: &[u8] = master_secret_key_vec.as_ref();
    let master_chain_code_vec: Vec<u8> = hex::decode(master_chain_code_hex).unwrap();
    let master_chain_code: &[u8] = master_chain_code_vec.as_ref();

    // let master_chain_code: &[u8] = hex::decode(master_chain_code_hex).unwrap().as_ref();

    let private_key = derive_with_path(
        SecretKey::from_slice(master_secret_key.clone()).unwrap(),
        master_chain_code.try_into().unwrap(),
        &derived_path,
    );
    hex::encode(private_key.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step1_generate_mnemonic() {
        let derived_path = [2147483692, 2147483708, 2147483648, 0, 0];
        assert_eq!(
            step3_master_kay_to_private_key(
                "5e01502044f205b98ba493971561284565e41f34f03494bb521654b0c35cb3a9".to_string(),
                "bccd1f17319e02baa4b2688f5656267d2eeaf8b49a49607e4b37efe815629c82".to_string(),
                derived_path
            ),
            "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659".to_string()
        );
    }
}
