//Module test for auth

#[cfg(test)]
mod test_auth{
    use bluesome_lib::auth::hash_check_password::*;

    #[test]
    fn hash_password_test(){
        let data = "hello world".to_string(); 
        let trust_result = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
        let result = verify_password(data.clone(), trust_result).unwrap();
        assert_eq!(result, data);
    }
}
