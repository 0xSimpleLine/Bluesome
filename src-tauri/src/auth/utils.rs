use rustc_serialize::hex::{ToHex, FromHex};

pub fn encode_to_hex(value: Vec<u8>) -> String{
    value.to_hex()
} 

pub fn decode_from_hex(value: &str) -> Result<Vec<u8>, String>{
    let val = value.from_hex()
        .expect("Impossible to decode from hexadecimal");
    Ok(val)
}
