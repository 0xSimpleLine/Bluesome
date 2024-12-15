use rustc_serialize::hex::{ToHex, FromHex};

pub fn encode_to_hex(value: Vec<u8>) -> String{
    value.to_hex()
} 

pub fn decode_from_hex(value: String) -> Result<Vec<u8>, String>{
    let val = value.from_hex().expect("Impossible to decode from hexadecimal");
    Ok(val)
}

// Data used for these tests comes from: https://github.com/google/boringssl/blob/master/crypto/cipher_extra/test/cipher_tests.txt
#[cfg(test)]
mod test_processing{
    use super::*;
    use app_crypto_lib::processing::encryption::*;
    use app_crypto_lib::processing::decryption::*;

    // Testing the encryption function for parameters
    #[test]
    fn param_encryption_test(){
        // Phase 1 (Simple test)
        let key_1 = decode_from_hex("0000000000000000000000000000000000000000000000000000000000000000".to_string()).unwrap();
        let nonce_1 = decode_from_hex("000000000000000000000000".to_string()).unwrap();
        let plaint_text_1 = "".as_bytes().to_vec();
        let cypher_text_1 = "".as_bytes().to_vec();
        let tag_1 = "530f8afbc74536b9a963b4f1c4cb738b";
        let result_1 = encrypt_params(key_1.as_slice(), nonce_1.as_slice(), plaint_text_1).unwrap();
        assert_eq!(encode_to_hex(result_1), tag_1.to_string());

        // Phase 2 (Hard test)
        let key_2 = decode_from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".to_string()).unwrap();
        let nonce_2 = decode_from_hex("cafebabefacedbaddecaf888".to_string()).unwrap();
        let plaint_text_2 = decode_from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255".to_string()).unwrap();
        let cipher_text_2 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let tag_2 =  "b094dac5d93471bdec1a502270e3cc6c";
        let result_2 = encrypt_params(key_2.as_slice(), nonce_2.as_slice(), plaint_text_2).unwrap();
        assert_eq!(encode_to_hex(result_2), format!("{}{}", cipher_text_2, tag_2));
    }

    // Testing the decryption function for parameters
    #[test]
    fn param_decryption_test(){
        // Phase 1 
        let key_1 = decode_from_hex("0000000000000000000000000000000000000000000000000000000000000000".to_string()).unwrap();
        let nonce_1 = decode_from_hex("000000000000000000000000".to_string()).unwrap();
        let plaint_text_1 = "".as_bytes().to_vec();
        let cypher_text_1 = "".as_bytes().to_vec();
        let tag_1 = decode_from_hex("530f8afbc74536b9a963b4f1c4cb738b".to_string()).unwrap();
        let result_1 = decrypt_params(key_1.as_slice(), nonce_1.as_slice(), tag_1).unwrap();
        assert_eq!(encode_to_hex(result_1), "");

        // Phase 2 
        let key_2 = decode_from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".to_string()).unwrap();
        let nonce_2 = decode_from_hex("cafebabefacedbaddecaf888".to_string()).unwrap();
        let plaint_text_2 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let cipher_text_2 = decode_from_hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c".to_string()).unwrap();
        let result_2 = decrypt_params(key_2.as_slice(), nonce_2.as_slice(), cipher_text_2).unwrap();
        assert_eq!(encode_to_hex(result_2), plaint_text_2.to_string());
    }

    //Testing the encryption function for secret
    #[test]
    fn secret_encryption_test(){
        // Phase 1
        let key_1 = decode_from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308".to_string()).unwrap();
        let nonce_1 = decode_from_hex("cafebabefacedbaddecaf888".to_string()).unwrap();
        let plaint_text_1 = decode_from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".to_string()).unwrap();
        let cipher_text_1 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let aad_1 = decode_from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2".to_string()).unwrap();
        let tag_1  = "76fc6ece0f4e1768cddf8853bb2d551b";
        let result_1 = encrypt_secret(key_1.as_slice(), nonce_1.as_slice(), aad_1.as_slice(), plaint_text_1).unwrap();
        assert_eq!(encode_to_hex(result_1), format!("{}{}", cipher_text_1, tag_1));
    }
}
