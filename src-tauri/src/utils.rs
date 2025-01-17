use std::{fs, str};
use rustc_serialize::hex::{ToHex, FromHex};

//Decode from hexadecimal
pub fn decode_from_hex(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_hex()
        .expect("Impossible to decode from hexadecimal");
    Ok(val)
}

//Encode to hexadecimal
pub fn encode_to_hex(value: Vec<u8>) -> String{
    value.to_hex()
}

// this function create a file and write in file
pub fn generate_file(file: &str, content: String) -> Result<(), String>{
    fs::write(file, content)
        .expect("Impossible to write in file");
    Ok(())
}
