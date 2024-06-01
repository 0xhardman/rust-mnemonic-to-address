use secp256k1::SecretKey;

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
    // # step 4 - master key to private key
    // With master key and chain code, we can derive the private key for the first account now.
    // Let's check the derivation path first.
    // `m / purpose' / coin_type' / account' / change / address_index`
    // m is the master key,
    // The purpose is 44' for BIP44, and the coin type is 0' for Bitcoin, 60' for Ethereum.
    // The account is the index of the account, starting from 0. You can define 0 as the main account for daily use, and 1 as the account for donate or anything else.
    // The Change field is used to differentiate between internal and external chains.
    // The Address Index is the index of the address in the chain. You can use it to generate multiple addresses.
    // To get the private key, we need to derive the private key from the master key with the path of each level.
    // the derivation function is defined as:
    // `CKDpriv((key_parent, chain_code_parent), i) -> (child_key_i, child_code_i)`
    // `i` is the level number.
    // CKDpriv= child key derivation (private)
    // Itereate the derivation function with the path, we can get the private key for the first account.

    // One more thing need to be mentioned is Apostrophe in the path indicates that BIP32 hardened derivation is used.
    // such as 44' is a hardened derivation, while 44 is not.
    // And 44' actually means 2^31+44, which is a hardened derivation.
    // "hardening" in BIP32 increases the security of derived keys by making it impossible to derive other child keys using just a public key and a child key, effectively preventing potential attackers from accessing your key hierarchy.

    #[test]
    fn test() {
        let derived_path = [(2 ^ 31) + 44, (2 ^ 31) + 60, 2 ^ 21, 0, 0];
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
