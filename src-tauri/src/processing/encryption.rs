use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce
};
use argon2::password_hash::rand_core::{OsRng, CryptoRng, RngCore};

//Generated a slice with size of 12 bytes (96 bits)
fn generate_rng_slice<R>(rng: &mut R) -> [u8; 12]
    where 
        R: CryptoRng + RngCore,
{
    let mut new_random = [0u8; 12];
    rng.fill_bytes(&mut new_random);
    new_random
}

//Geneated the nonce to encrypt and decrypt data
pub fn generate_salts() -> [u8; 12]{
    generate_rng_slice(&mut OsRng)
}

// To encrypt data from database
pub fn encrypt_secret(key: &[u8], nonce: &[u8], ad: &[u8], plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut cipher_text = plaint_text;
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt_in_place(nonce, ad.as_ref(), &mut cipher_text).expect("Encryption failed");
    Ok(cipher_text)
}

// To encrypt params from database
pub fn encrypt_params(key: &[u8], nonce: &[u8], plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    let cipher_text = cipher.encrypt(nonce, plaint_text.as_ref()).expect("Encryption failed");
    Ok(cipher_text)
}
