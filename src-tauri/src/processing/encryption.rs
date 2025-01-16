use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce
};
use argon2::password_hash::rand_core::{OsRng, CryptoRng, RngCore};

//Generate a slice with size of 12 bytes (96 bits)
fn generate_rng_slice<R>(rng: &mut R) -> Vec<u8>
    where 
        R: CryptoRng + RngCore,
{
    let mut new_random = vec![0u8; 12];
    rng.fill_bytes(&mut new_random);
    new_random
}

//Geneate nonce to encrypt and decrypt data
pub fn generate_nonce() -> Vec<u8>{
    generate_rng_slice(&mut OsRng)
}

//encrypt secret from database
pub fn encrypt_secret(key: &[u8], nonce: Vec<u8>, ad: Vec<u8>, plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut cipher_text = plaint_text;
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce.as_slice());
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt_in_place(nonce, ad.as_slice(), &mut cipher_text).expect("Encryption failed");
    Ok(cipher_text)
}

//encrypt params from database
pub fn encrypt_params(key: &[u8], nonce: Vec<u8>, plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce.as_slice());
    let cipher = Aes256Gcm::new(key);
    let cipher_text = cipher.encrypt(nonce, plaint_text.as_ref()).expect("Encryption failed");
    Ok(cipher_text)
}
