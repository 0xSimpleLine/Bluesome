// hash_check_password is a module who inclue all function to hash and verify
// the user's password

use std::fs;
use crate::utils::{generate_file};
use sha2::{Sha256, Digest};
use base64ct::{Base64, Encoding};

//Hash function
pub fn hash(password: &String) -> String{
    let hasher = Sha256::digest(password);
    Base64::encode_string(&hasher)
} 

//Stock password in file
pub fn stock_password(password: String) -> Result<(), String>{
    match generate_file("file.txt", password){
        Ok(v) => Ok(v),
        Err(e) => Err(e)
    }
}

//Read file and return his content
pub fn read_file() -> Result<String, String>{
    let content = fs::read_to_string("file.txt")
        .expect("Impossible to read file");
    Ok(content)
}

// This function allow to verify if the password is correct
// and protect against the contant time attacks
fn cmp_const_time(password: &[u8], trust_password: &[u8], size: usize) -> u8{
    let mut result = 0;

    for i in 0..size{
        result |= password[i] ^ trust_password[i];
    }
    result
}

//Verify password function
pub fn verify_password(password: String, trust_password: String) -> Result<String, String>{
    let output = password.as_bytes();
    let trust = trust_password.as_bytes();
    let size = output.len();
    let result = cmp_const_time(output, trust, size);
    if result == 0{
        Ok(password)
    } else{
        Err(String::from("Password is Incorrect"))
    }
}
