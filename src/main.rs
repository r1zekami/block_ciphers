#![allow(unused)]

mod aes; use aes::AES;
mod des; use des::DES;
mod magma; use magma::MAGMA;

/*
Test vectors from:
NIST Special Publication 800-17 (Table 2)   DES
NIST FIPS 197                               AES
GOST_R_3412-2015                            MAGMA
*/

fn main() {
    aes_test();
    des_test();
    magma_test();
}


fn aes_test() {
    println!("\n=== AES Test ===");
    let aes_data: u128 = 0x00112233445566778899aabbccddeeff;
    let aes_key: Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    println!("MSG: {:032X}", aes_data);
    print!("KEY: ");
    for byte in &aes_key {
        print!("{:02X}", byte);
    }
    println!();
    let aes_ciphertext: u128 = AES::encrypt(aes_data, aes_key.clone());
    let aes_decrypted: u128 = AES::decrypt(aes_ciphertext, aes_key);
    println!("ENC: {:032X}", aes_ciphertext);
    println!("DEC: {:032X}", aes_decrypted);
}


fn des_test() {
    println!("\n=== DES Test ===");
    let des_data: u64 = 0x0000000000000000;
    let des_key: u64 = 0x8001010101010101;
    println!("MSG: {:016X}", des_data);
    println!("KEY: {:016X}", des_key);
    let des_ciphertext = DES::encrypt(des_data, des_key);
    let des_decrypted = DES::decrypt(des_ciphertext, des_key);
    println!("ENC: {:016X}", des_ciphertext);
    println!("DEC: {:016X}", des_decrypted);
}


fn magma_test() {
    println!("\n=== MAGMA Test ===");
    let magma_plaintext: u64 = 0xfedcba9876543210;
    let magma_key: [u8; 32] = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];
    println!("MSG: {:016X}", magma_plaintext);
    print!("KEY: ");
    for byte in magma_key.iter() {
        print!("{:02X}", byte);
    }
    println!();
    let magma_ciphertext = MAGMA::encrypt(magma_plaintext, magma_key);
    let magma_decrypted = MAGMA::decrypt(magma_ciphertext, magma_key);
    println!("ENC: {:016X}", magma_ciphertext);
    println!("DEC: {:016X}", magma_decrypted);
}
