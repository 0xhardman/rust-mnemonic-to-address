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

use crate::utils::{curve_point_from_int, derive_with_path, serialize_curve_point};

// use sha2::{Digest, Sha256};

fn step5_private_key_to_public_key(private_key_hex: String) -> String {
    let private_key_vec = hex::decode(private_key_hex).unwrap();
    let private_key = SecretKey::from_slice(private_key_vec.as_ref()).unwrap();
    let publicKey = curve_point_from_int(private_key);
    hex::encode(serialize_curve_point(publicKey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step1_generate_mnemonic() {
        assert_eq!(
            step5_private_key_to_public_key(
                "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659".to_string(),
            ),
            "0226cc24348fbe0c2912fbb0aa4408e089bb0ae488a88ac46bb13290629a737646".to_string()
        );
    }
}
