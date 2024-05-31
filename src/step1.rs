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
    use bip39::{Language, Mnemonic};
    #[test]
    fn test() {
        // # Step 1 - Generate Mnemonic
        // Mnemonic is a list of words, which is easy to remember and write.
        // And do you think that mnemonic is generated randomly?
        // Hesitate, it is not completely random. Let me explain.
        // Each word in the mnemonic can be represented by a number from 0 to 2047, total 2048 numbers.
        // Such as "indoor" is 920, "dish" is 505, "abandon" is 0. You can get more information from the BIP39 [wordlist](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
        // And then we can convert the mnemonic to a binary number, such as "indoor" is 920, the binary number is 1110011000. Each of them is 11 bits.
        // In other words we can randomly generate a string of 01 combinations as mnemonic's material. And the length of the string is a multiple of 32.
        // Also that means the length of the mnemonic is a multiple of 3, but maximum 24 words. The more words, the more secure.
        // To make sure the Raw Binary is valid, we need to calculate the checksum of the Raw Binary.
        // The checksum is the first several bits of the SHA256 hash of the Raw Binary.
        // mnemonic = Raw Binary + checksum
        // checksum = SHA256(Raw Binary)[:len(01_string)/32]

        // ## Example
        // Mnemonic: indoor dish desk flag debris potato excuse depart ticket judge file exit
        // Raw Binary: 01110011000 00111111001 00111011111 01011000001 00111000011 10101000110 01001111000 00111010110 11100001101 01111000101 01010110001 01001111111
        // Checksum: 1111 (Tail 4(128/32) bits of SHA256(Raw Binary[0:128]))

        step1_generate_mnemonic();
    }
}
