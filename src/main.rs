use std::str::Bytes;

use bip39::{Language, Mnemonic, MnemonicType, Seed};

use bitcoin_hashes::{ripemd160, Hash};
use ring::{digest, hmac, rand};

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

// use sha2::{Digest, Sha256};

fn main() {
    // 生成助记词
    // let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    //season aunt saddle mansion claw skirt enhance coach lizard knock diary picnic
    let mnemonic = Mnemonic::from_phrase(
        "indoor dish desk flag debris potato excuse depart ticket judge file exit",
        Language::English,
    )
    .unwrap();
    let phrase = mnemonic.phrase();
    println!("Generated Mnemonic: {}", phrase);

    // 从助记词生成种子
    let seed = Seed::new(&mnemonic, "");

    let seed_bytes = seed.as_bytes();
    // let seed_bytes = b"000102030405060708090a0b0c0d0e0f";
    println!("Generated Seed: {}", hex::encode(seed_bytes));

    let key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");

    let tag = hmac::sign(&key, seed_bytes);
    println!(
        "length:{}, tag: {}",
        tag.as_ref().len(),
        hex::encode(tag.as_ref())
    );
    let (il, ir) = tag.as_ref().split_at(32);

    let master_secret_key = il; // 处理以赋予这部分的数据实际意义依赖于具体上下文
    let master_chain_code = ir;
    println!("master_secret_key: {}", hex::encode(master_secret_key));
    println!("master_chain_code: {}", hex::encode(master_chain_code));

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
    let key_bytes = [&[0x00], il].concat();

    // let master_chain_code = [0x00; 32]; // Placeholder, replace with actual master_chain_code
    let all_parts = [
        version_bytes,
        &depth_byte,
        &parent_fingerprint,
        &child_number_bytes,
        &master_chain_code,
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

    let root_key = bs58::encode(payload_and_checksum);
    // println!("root_key: {:?}", root_key.);
    println!("root_key: {}", root_key.into_string());
}

// Serialize a public key in compressed format.
fn serialize_curve_point(p: PublicKey) -> Vec<u8> {
    let serialized = p.serialize();
    Vec::from(serialized)
}

// Create a public key from a scalar (private key).
fn curve_point_from_int(k: SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &k)
}

// Calculate the fingerprint for a private key.
fn fingerprint_from_private_key(k: SecretKey) -> Vec<u8> {
    let pk = curve_point_from_int(k);

    // Serialize the public key in compressed format
    let pk_compressed = serialize_curve_point(pk);

    // Perform SHA256 hashing
    let sha256_result = digest::digest(&digest::SHA256, &pk_compressed);

    // Perform RIPEMD160 hashing

    let ripemd_result = ripemd160::Hash::hash(sha256_result.as_ref());

    // Return the first 4 bytes as the fingerprint
    ripemd_result[0..4].to_vec()
}

// type HmacSha512 = Hmac<Sha512>;

// Derived ExtPrivate key
fn derive_ext_private_key(
    private_key: SecretKey,
    chain_code: &[u8],
    child_number: u32,
) -> (SecretKey, Vec<u8>) {
    let key = hmac::Key::new(hmac::HMAC_SHA512, chain_code);

    let mut data = if child_number >= (1 << 31) {
        [&[0u8], &private_key[..]].concat()
    } else {
        private_key.as_ref().to_vec()
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

    (child_private_key, child_chain_code)
}