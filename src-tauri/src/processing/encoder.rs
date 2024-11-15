use rustc_serialize::base64::{STANDARD, ToBase64, FromBase64};

//encode String to base64
pub fn encode_to_bae64(value: Vec<u8>) -> String{
    value.to_base64(STANDARD)
}

//decode base64 to String
pub fn decode_from_hex(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_base64().expect("Impossible to encode this data to hexadecimal");
    Ok(val)
}
