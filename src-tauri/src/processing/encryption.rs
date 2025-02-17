use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce
};
use argon2::password_hash::rand_core::{OsRng, CryptoRng, RngCore};

//Generate a slice with size of 12 bytes (96 bits)
fn generate_rng_slice<R>(rng: &mut R, new_random: &mut Vec<u8>)
    where 
        R: CryptoRng + RngCore,
{
    rng.fill_bytes(new_random);
}

//Geneate nonce for encrypting and decrypting data
pub fn generate_nonce() -> Vec<u8>{
    let mut new_random = vec![0u8; 12];
    generate_rng_slice(&mut OsRng, &mut new_random);
    return new_random;
}

//Generate an AD for encrypting and decrypting data
pub fn generate_ad() -> Vec<u8> {
    let mut new_random = vec![0u8; 32];
    generate_rng_slice(&mut OsRng, &mut new_random);
    return new_random;
}

//encrypt secret from database
pub fn encrypt_secret(key: &[u8], nonce: &[u8], ad: &[u8], plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut cipher_text = plaint_text;
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt_in_place(nonce, ad, &mut cipher_text).expect("Encryption failed");
    Ok(cipher_text)
}

//encrypt params from database
pub fn encrypt_params(key: &[u8], nonce: &[u8], plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    let cipher_text = cipher.encrypt(nonce, plaint_text.as_ref()).expect("Encryption failed");
    Ok(cipher_text)
}
