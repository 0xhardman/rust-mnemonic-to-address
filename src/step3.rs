use ring::hmac;

// use sha2::{Digest, Sha256};

fn step3_seed_to_master_kay(seed_hex: &String) -> (String, String) {
    let seed_bytes = hex::decode(seed_hex).unwrap();

    let key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let tag = hmac::sign(&key, &seed_bytes);

    let (il, ir) = tag.as_ref().split_at(32);
    (hex::encode(il), hex::encode(ir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let seed_hex="3bd0bda567d4ea90f01e92d1921aacc5046128fd0e9bee96d070e1d606cb79225ee3e488bf6c898a857b5f980070d4d4ce9adf07d73458a271846ef3a8415320".to_string();
        assert_eq!(
            step3_seed_to_master_kay(&seed_hex),
            (
                "5e01502044f205b98ba493971561284565e41f34f03494bb521654b0c35cb3a9".to_string(),
                "bccd1f17319e02baa4b2688f5656267d2eeaf8b49a49607e4b37efe815629c82".to_string()
            )
        );
    }
}
