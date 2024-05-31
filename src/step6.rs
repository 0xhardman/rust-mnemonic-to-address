use secp256k1::PublicKey;
use tiny_keccak::{Hasher, Keccak};

fn step6_public_key_to_address(pub_key_hex: String) -> String {
    let public_key_vec = hex::decode(pub_key_hex).unwrap();
    let public_key = PublicKey::from_slice(public_key_vec.as_ref()).unwrap();
    let serialized_pub_key = public_key.serialize_uncompressed();
    let public_key_bytes = &serialized_pub_key[1..];
    let mut hasher = Keccak::v256();
    hasher.update(public_key_bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    let address = &output[12..];
    hex::encode(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    // # step 6 - public key to address
    // The address is the last 20 bytes of the Keccak-256 hash of the public key.

    #[test]
    fn test() {
        assert_eq!(
            step6_public_key_to_address(
                "0226cc24348fbe0c2912fbb0aa4408e089bb0ae488a88ac46bb13290629a737646".to_string(),
            ),
            "3f1eae7d46d88f08fc2f8ed27fcb2ab183eb2d0e".to_string()
        );
    }
}
