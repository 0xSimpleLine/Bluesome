use rustc_serialize::hex::{ToHex, FromHex};

pub fn encode_to_hex(value: Vec<u8>) -> String{
    value.to_hex()
} 

pub fn decode_from_hex(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_hex().expect("Impossible to decode from hexadecimal");
    Ok(val)
}

#[cfg(test)]
mod test_processing{
    use super::*;
    use app_crypto_lib::processing::encryption::*;
    use app_crypto_lib::processing::decryption::*;

    #[test]
    fn param_encryption_test(){
        let key = decode_from_hex("0000000000000000000000000000000000000000000000000000000000000000".to_string()).unwrap();
        let nonce = decode_from_hex("000000000000000000000000".to_string()).unwrap();
        let plaint_text = "".as_bytes().to_vec();
        let cypher_text = "".as_bytes().to_vec();
        let tag = "530f8afbc74536b9a963b4f1c4cb738b";
        let result = encrypt_params(key.as_slice(), nonce.as_slice(), plaint_text).unwrap();
        assert_eq!(encode_to_hex(result), tag.to_string());
    }
}
