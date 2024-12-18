use rustc_serialize::{hex::{ToHex, FromHex}, base64::{STANDARD, ToBase64, FromBase64}};

//encode String to base64
pub fn encode_to_base64(value: Vec<u8>) -> String{
    value.to_base64(STANDARD)
}

//decode base64 to String
pub fn decode_from_base64(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_base64().expect("Impossible to decode from base64");
    Ok(val)
}

pub fn encode_to_hex(value: Vec<u8>) -> String{
    value.to_hex()
} 

pub fn decode_from_hex(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_hex().expect("Impossible to decode from hexadecimal");
    Ok(val)
}
