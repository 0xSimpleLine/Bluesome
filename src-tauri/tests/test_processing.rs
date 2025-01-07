// Module test for processing data 
// Data used for these tests comes from: https://github.com/google/boringssl/blob/master/crypto/cipher_extra/test/cipher_tests.txt
#[cfg(test)]
mod test_processing{
    use bluesome_lib::processing::encryption::*;
    use bluesome_lib::processing::decryption::*;
    use bluesome_lib::utils::{encode_to_hex, decode_from_hex};
    use hex_literal::hex;

    // Test the encryption and decryption function for parameters
    #[test]
    fn param_encryption_decryption_test(){
        // Phase 1 (Simple test)
        //Keys
        let key_1 = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_2 = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

        //Nonces
        let nonce_1 = hex!("000000000000000000000000").to_vec();
        let nonce_2 = hex!("cafebabefacedbaddecaf888").to_vec();

        //Plaint text
        let plaint_text_1 = "".as_bytes().to_vec();
        let plaint_text_2 = decode_from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255".to_string()).unwrap();
        let plaint_text_3 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";

        //Tags
        let tag_1 = "530f8afbc74536b9a963b4f1c4cb738b";
        let tag_2 = decode_from_hex("530f8afbc74536b9a963b4f1c4cb738b".to_string()).unwrap();
        let tag_3 =  "b094dac5d93471bdec1a502270e3cc6c";

        //Cipher text
        let cipher_text_1 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let cipher_text_2 = decode_from_hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c".to_string()).unwrap();

        //Phase 1
        let result_encrypt = encrypt_params(key_1.as_slice(), nonce_1.clone(), plaint_text_1).unwrap();
        assert_eq!(encode_to_hex(result_encrypt), tag_1.to_string());

        let result_encrypt = encrypt_params(key_2.as_slice(), nonce_2.clone(), plaint_text_2).unwrap();
        assert_eq!(encode_to_hex(result_encrypt), format!("{}{}", cipher_text_1, tag_3));

        // Phase 2
        let result_1 = decrypt_params(key_1.as_slice(), nonce_1, tag_2).unwrap();
        assert_eq!(encode_to_hex(result_1), "");

        // Phase 3 
        let result_2 = decrypt_params(key_2.as_slice(), nonce_2, cipher_text_2).unwrap();
        assert_eq!(encode_to_hex(result_2), plaint_text_3.to_string());
    }

    //Test the encryption and decryption function for secrets
    #[test]
    fn secret_encryption_decryption_test(){
        // Key
        let key_1 = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let key_2 = hex!("ca2b4d335598f26d3d3607e62b9ef853d3543e741350f92f3050894721d3d450");

        //Nonce
        let nonce_1 = hex!("cafebabefacedbaddecaf888").to_vec();
        let nonce_2 = hex!("2431b5cee8c3ecec4caad278").to_vec();

        //plaint text
        // plaint text decoded
        let plaint_text_1 = decode_from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".to_string()).unwrap();
        let plaint_text_2 = decode_from_hex("75e29e46350d1fa99403b1e5baa414e41a8e714910f313f8e850cf3076508ff650011af766b51283fbd5626166d775fd4b4cb7124d26d77b41eb17bf642bf67a34c1caf0fa9b43eec12103f864e56c5ccdc81b89c1a35e394362688d05dd94eda3d05dd2".to_string()).unwrap();
        // plaint text no decoded
        let plaint_text_3 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let plaint_text_4 = "75e29e46350d1fa99403b1e5baa414e41a8e714910f313f8e850cf3076508ff650011af766b51283fbd5626166d775fd4b4cb7124d26d77b41eb17bf642bf67a34c1caf0fa9b43eec12103f864e56c5ccdc81b89c1a35e394362688d05dd94eda3d05dd2";

        //Cipher text
        //cipher text no decoded
        let cipher_text_1 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let cipher_text_2 = "90c13ec26d01b7b96bdd6816d3ee57df57efeabdb15ba602229ff71d71793fe8081eb1b462e8b2967bc4af96fd6dc72cee3d2b6495c7f04c9068b2ad0b073e11cd5999df541ad705c6315eefa8da49c5dbc258f7ba922908489c1ce672971c3bfb6e8482";
        //cipher text decoded
        let cipher_text_3 = decode_from_hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b".to_string()).unwrap();
        let cipher_text_4 = decode_from_hex("90c13ec26d01b7b96bdd6816d3ee57df57efeabdb15ba602229ff71d71793fe8081eb1b462e8b2967bc4af96fd6dc72cee3d2b6495c7f04c9068b2ad0b073e11cd5999df541ad705c6315eefa8da49c5dbc258f7ba922908489c1ce672971c3bfb6e84823a7741a094be92b838850c32e4b06c6d".to_string()).unwrap();

        //AD 
        let ad_1 = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2").to_vec();
        let ad_2  = hex!("31c3ce532bc1bae65b5ced69449129b112019cc6078268b853dd17c41832ecae07f9c6b068ef6cba2b55f352904afd6096ff8432081aed408d9340c319fd8e2029c389b6e3a4bdc38853444c3f7be9385ff1ca27e59c43b542e99799bb4ce56b8e26d6c1").to_vec();

        //Tag
        let tag_1  = "76fc6ece0f4e1768cddf8853bb2d551b";
        let tag_2 = "3a7741a094be92b838850c32e4b06c6d";

        //Assertion
        // Phase 1
        let result_1 = encrypt_secret(key_1.as_slice(), nonce_1.clone(), ad_1.clone(), plaint_text_1).unwrap();
        assert_eq!(encode_to_hex(result_1), format!("{}{}", cipher_text_1, tag_1));

        // Phase 2
        let result_2 = encrypt_secret(key_2.as_slice(), nonce_2.clone(), ad_2.clone(), plaint_text_2).unwrap();
        assert_eq!(encode_to_hex(result_2), format!("{}{}", cipher_text_2, tag_2));
    
        // Phase 3
        let result_3 = decrypt_secret(key_1.as_slice(), nonce_1, ad_1, cipher_text_3).unwrap();
        assert_eq!(encode_to_hex(result_3), format!("{}", plaint_text_3));

        // Phase 4
        let result_2 = decrypt_secret(key_2.as_slice(), nonce_2, ad_2, cipher_text_4).unwrap();
        assert_eq!(encode_to_hex(result_2), format!("{}", plaint_text_4));
    }
}
