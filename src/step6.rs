use secp256k1::SecretKey;

use crate::utils::{curve_point_from_int, serialize_curve_point};

fn step5_private_key_to_public_key(private_key_hex: String) -> String {
    let private_key_vec = hex::decode(private_key_hex).unwrap();
    let private_key = SecretKey::from_slice(private_key_vec.as_ref()).unwrap();
    let public_key = curve_point_from_int(private_key);
    hex::encode(serialize_curve_point(public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            step5_private_key_to_public_key(
                "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659".to_string(),
            ),
            "0226cc24348fbe0c2912fbb0aa4408e089bb0ae488a88ac46bb13290629a737646".to_string()
        );
    }
}
