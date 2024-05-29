use bip39::{Language, Mnemonic};

// use sha2::{Digest, Sha256};

fn step1_generate_mnemonic() {
    // generate mnemonic
    let entropy = &[
        0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84, 0x6A,
        0x79,
    ];
    let mnemonic = Mnemonic::from_entropy(entropy, Language::English).unwrap();

    // let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    // let mnemonic: Mnemonic = Mnemonic::from_phrase(
    //     "indoor dish desk flag debris potato excuse depart ticket judge file exit",
    //     Language::English,
    // )
    // .unwrap();
    let phrase = mnemonic.phrase();
    println!("Generated Mnemonic: {}", phrase);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step1_generate_mnemonic() {
        step1_generate_mnemonic();
    }
}
