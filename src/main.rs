mod step1;
mod step2;
mod step3;
mod step4;
mod step6;
mod step5;
mod utils;

use bip39::{Language, Mnemonic, Seed};
use ring::hmac;
use secp256k1::SecretKey;
use tiny_keccak::{Hasher, Keccak};

use utils::{curve_point_from_int, derive_with_path, get_root_key, serialize_curve_point};

// use sha2::{Digest, Sha256};

fn main() {
    // generate mnemonic
    // let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let mnemonic: Mnemonic = Mnemonic::from_phrase(
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

    let root_key = get_root_key(master_secret_key, master_chain_code);
    // println!("root_key: {:?}", root_key.);
    println!("root_key: {}", root_key);

    let private_key = derive_with_path(
        SecretKey::from_slice(master_secret_key).unwrap(),
        master_chain_code.try_into().unwrap(),
        &[2147483692, 2147483708, 2147483648, 0, 0],
    );
    println!("private_key: {:?}", hex::encode(private_key.as_ref()));

    let public_key = curve_point_from_int(private_key);
    println!(
        "public_key: {:?}",
        hex::encode(serialize_curve_point(public_key))
    );

    // Hash the concatenated x and y public key point values:
    let serialized_pub_key = public_key.serialize_uncompressed();
    let public_key_bytes = &serialized_pub_key[1..];

    let mut hasher = Keccak::v256();
    hasher.update(public_key_bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    let address = &output[12..];
    println!("address: {:?}", hex::encode(address));
}
