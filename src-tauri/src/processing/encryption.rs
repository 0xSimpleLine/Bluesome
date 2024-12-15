use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce
};

// To encrypt data from database
pub fn encrypt_secret(key: &[u8], nonce: &[u8], da: &[u8], plaint_text: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut cipher_text = plaint_text;
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt_in_place(nonce, da.as_ref(), &mut cipher_text).expect("Encryption failed");
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
