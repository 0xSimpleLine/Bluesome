//Module test for auth

#[cfg(test)]
mod test_auth{
    use bluesome_lib::auth::{hash_check_password::*, key_derivation::*};

    #[test]
    fn hash_password_test(){
        //Phase 1
        let data_1 = "hello world".to_string(); 
        let trust_result_1 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
        let result_1 = verify_password(data_1.clone(), trust_result_1).unwrap();
        assert_eq!(result_1, data_1);

        //Phase 2
        let data_2 = "de188941a3375d3a8a061e67576e926d".to_string();
        let trust_result_2 = "57e918cfef3bd4ecd82e1e01771a60efa713df3d3281f61c785b7f7920e853b7".to_string();
        let result_2 = verify_password(data_2.clone(), trust_result_2).unwrap();
        assert_eq!(result_2, data_2);
    }

    #[test]
    fn test_derivate_key(){
        let salts = generate_salts();
        let password = b"Kj8#mP9$vL2@nX4&hR5wQ7!cY3%bN";
        let result = derivate_key(password, salts[0], salts[1]).unwrap();
        assert_ne!(result, vec![[0u8;32], [0u8;32]]);
    }
}
