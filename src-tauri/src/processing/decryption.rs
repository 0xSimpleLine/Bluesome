use aes_gcm::{
    aead::{Aead, AeadInPlace, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce
};

// To decrypt data from database
pub fn decrypt_data(key: &[u8], nonce: &[u8], da: [u8; 32], cipher_text: Vec<u8>) -> Result<Vec<u8>, String>{
    let mut plaint_text = cipher_text;
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt_in_place(nonce, da.as_ref(), &mut plaint_text).expect("Decryption failed");
    Ok(plaint_text)
}

// To decrypt params from database
pub fn decrypt_params(key: &[u8], nonce: &[u8], cipher_text: Vec<u8>) -> Result<Vec<u8>, String>{
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    let plaint_text = cipher.decrypt(nonce, cipher_text.as_ref()).expect("Decryption failed");
    Ok(plaint_text)
}
