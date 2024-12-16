use sha2::{sha256, Digest};

pub fn hash(password: String) -> String{
    let mut hasher = Sha256::new();
    hasher.update(password);
    return hasher.finalize();
} 


pub fn verify_password(password: String, trust_password: String) -> Result<String, String>{
    let hash_password = hash(password);
    if hash_password == trust_password {
        Ok(password);
    } else{
        Err("Password is incorrect");
    }
}
