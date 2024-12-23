use sha2::{Sha256, Digest};
use base64ct::{Base64, Encoding};

pub fn hash(password: &String) -> String{
    let hasher = Sha256::digest(password);
    Base64::encode_string(&hasher)
} 

pub fn verify_password(password: String, trust_password: String) -> Result<String, String>{
    let output = hash(&password);
    if output == trust_password {
        return Ok(password);
    } else{
        return Err("Password is incorrect".to_string());
    }
}
