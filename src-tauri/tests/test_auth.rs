//Module test for auth

#[cfg(test)]
mod test_auth{
    use bluesome_lib::auth::{hash_check_password::*, key_derivation::*};
    use hex_literal::hex;
    use base64ct::{Base64, Encoding};
    use std::fs;

    #[test]
    fn hash_password_test(){
        //Phase 1
        let data_1 = "hello world".to_string(); 
        stock_password(Base64::encode_string(&hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"))).unwrap();
        let trust_result_1 = read_file().unwrap();
        let result_1 = verify_password(hash(&data_1), trust_result_1.clone()).unwrap();
        assert_eq!(trust_result_1, result_1);

        //Phase 2
        let data_2 = "de188941a3375d3a8a061e67576e926d".to_string();
        stock_password(Base64::encode_string(&hex!("57e918cfef3bd4ecd82e1e01771a60efa713df3d3281f61c785b7f7920e853b7"))).unwrap();
        let trust_result_2 = read_file().unwrap();
        let result_2 = verify_password(hash(&data_2), trust_result_2.clone()).unwrap();
        assert_eq!(trust_result_2, result_2);

        fs::remove_file("file.txt").unwrap();
    }

    #[test]
    fn test_derivate_key(){
        let salts = generate_salts();
        let password = b"Kj8#mP9$vL2@nX4&hR5wQ7!cY3%bN";
        let result = derivate_key(password, salts[0].clone(), salts[1].clone()).unwrap();
        assert_ne!(result, vec![[0u8;32], [0u8;32]]);
    }
}
