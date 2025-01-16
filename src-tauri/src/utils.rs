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
