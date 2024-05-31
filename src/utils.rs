use bitcoin_hashes::{ripemd160, Hash};
use ring::{digest, hmac};

// use secp256k1::hashes::{sha256, Hash};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

// Serialize a public key in compressed format.
pub fn serialize_curve_point(p: PublicKey) -> Vec<u8> {
    let serialized = p.serialize();
    Vec::from(serialized)
}

// Create a public key from a scalar (private key).
pub fn curve_point_from_int(k: SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &k)
}

// Calculate the fingerprint for a private key.
pub fn fingerprint_from_private_key(k: SecretKey) -> [u8; 4] {
    let pk = curve_point_from_int(k);

    // Serialize the public key in compressed format
    let pk_compressed = serialize_curve_point(pk);

    // Perform SHA256 hashing
    let sha256_result = digest::digest(&digest::SHA256, &pk_compressed);

    // Perform RIPEMD160 hashing

    let ripemd_result = ripemd160::Hash::hash(sha256_result.as_ref());

    // Return the first 4 bytes as the fingerprint
    ripemd_result[0..4].try_into().unwrap()
}

// type HmacSha512 = Hmac<Sha512>;

// Derived ExtPrivate key
pub fn derive_ext_private_key(
    private_key: SecretKey,
    chain_code: &[u8],
    child_number: u32,
) -> (SecretKey, [u8; 32]) {
    let key = hmac::Key::new(hmac::HMAC_SHA512, chain_code);

    let mut data = if child_number >= (1 << 31) {
        [&[0u8], &private_key[..]].concat()
    } else {
        let p = curve_point_from_int(private_key);
        serialize_curve_point(p)
        // private_key.as_ref().to_vec()
    };
    data.extend_from_slice(&child_number.to_be_bytes());

    let hmac_result = hmac::sign(&key, &data);

    let (l, r) = hmac_result.as_ref().split_at(32);

    let l = (*l).to_owned();
    let r = (*r).to_owned();

    let mut l_32 = [0u8; 32];
    l_32.clone_from_slice(&l);

    let private_byte = private_key.as_ref();

    let l_secret = SecretKey::from_slice(&l).unwrap();
    let child_private_key = l_secret
        .add_tweak(&Scalar::from_be_bytes(*private_byte).unwrap())
        .unwrap();
    let child_chain_code = r;

    (child_private_key, child_chain_code.try_into().unwrap())
}

pub fn derive_with_path(
    master_private_key: SecretKey,
    master_chain_code: [u8; 32],
    path_numbers: &[u32; 5],
) -> SecretKey {
    let mut depth = 0;

    let mut child_number: Option<u32> = None;
    let mut private_key = master_private_key;
    let mut chain_code = master_chain_code;

    for &i in path_numbers {
        depth += 1;
        println!("depth: {}", depth);

        child_number = Some(i);
        println!("child_number: {:?}", child_number);

        (private_key, chain_code) = derive(child_number.unwrap(), private_key, chain_code);
    }
    private_key
}

pub fn derive(
    child_number: u32,
    private_key: SecretKey,
    chain_code: [u8; 32],
) -> (SecretKey, [u8; 32]) {
    println!("child_number: {:?}", child_number);

    let child_fingerprint = fingerprint_from_private_key(private_key.clone());
    println!("child_fingerprint: {:?}", hex::encode(child_fingerprint));

    let derived = derive_ext_private_key(private_key.clone(), &chain_code, child_number);
    let private_key = derived.0;
    let chain_code = derived.1;

    println!("private_key: {:?}", hex::encode(private_key.as_ref()));
    println!("chain_code: {:?}\n", hex::encode(chain_code));

    (private_key, chain_code)
}

pub fn get_root_key(private_key: &[u8], chain_code: &[u8]) -> String {
    let version_bytes = [
        ("mainnet_public", "0488b21e"),
        ("mainnet_private", "0488ade4"),
        ("testnet_public", "043587cf"),
        ("testnet_private", "04358394"),
    ]
    .iter()
    .cloned()
    .map(|(k, v)| (k, hex::decode(v).unwrap()))
    .collect::<std::collections::HashMap<_, _>>();

    let version_bytes = version_bytes.get("mainnet_private").unwrap().as_slice();
    let depth_byte = [0x00];
    let parent_fingerprint = [0x00; 4];
    let child_number_bytes = [0x00; 4];
    // This is a placeholder for `L` from the original code
    // Assuming `L` is a byte array which is prefixed with a zero byte in `key_bytes`
    // let l = [0x00; 33]; // Placeholder, replace it with actual `L`
    let key_bytes = [&[0x00], private_key].concat();

    // let master_chain_code = [0x00; 32]; // Placeholder, replace with actual master_chain_code
    let all_parts = [
        version_bytes,
        &depth_byte,
        &parent_fingerprint,
        &child_number_bytes,
        &chain_code,
        &key_bytes,
    ]
    .concat();

    let checksum = digest::digest(
        &digest::SHA256,
        &digest::digest(&digest::SHA256, &all_parts).as_ref(),
    );
    let checksum = &checksum.as_ref()[..4]; // T
    let payload_and_checksum = [&all_parts, checksum].concat();
    // for part in all_parts.iter() {
    //     println!("{}", (part));
    // }

    bs58::encode(payload_and_checksum).into_string()
}
