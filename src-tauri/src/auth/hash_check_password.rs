use sha2::{Sha256, Digest};
use crate::auth::utils::*;

pub fn hash(password: &String, output: &mut [u8]){
    let hasher = Sha256::digest(password);
    output.copy_from_slice(&hasher);
} 

pub fn verify_password(password: String, trust_password: String) -> Result<String, String>{
    let mut output = vec![0u8; 32];
    hash(&password, &mut output);
    if encode_to_hex(output) == trust_password {
        return Ok(password);
    } else{
        return Err("Password is incorrect".to_string());
    }
}
