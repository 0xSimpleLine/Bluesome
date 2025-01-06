// Unit test for database operations

#[cfg(test)]
mod test_db {
    use bluesome_lib::{database::*, types::*};
    use std::fs;
   
    #[test]
    fn test_first_opt(){
        let param = Param{
            id: String::from("foo").into(),
            ad: String::from("foo").into(),
            salt1: String::from("foo").into(),
            salt2: String::from("foo").into()
        };

        let secret = Secret{
            id: String::from("foo"),
            message: String::from("foo")
        };

        let mut _secret = Secret{
            id: String::from("bar"),
            message: String::from("bar")
        };

        generate_db_name().unwrap();
        let db_name = read_db_file().unwrap();

        create_db_tables(&db_name, param).unwrap();
        create_new_secret(&db_name, secret.clone()).unwrap();
        create_new_secret(&db_name, _secret.clone()).unwrap();

        let secrets = read_all_secrets(&db_name).unwrap();
        let secret_ = read_secret(&db_name, "foo").unwrap();

        assert_eq!(secrets, vec![secret.clone(), _secret.clone()]);
        assert_eq!(secret_, secret.message);

        _secret.message = "foo".to_string();
        update_secret(&db_name, _secret.clone()).unwrap();
        assert_eq!(_secret.message, "foo".to_string());

        remove_secret(&db_name,_secret.id).unwrap();
        let _secrets = read_all_secrets(&db_name).unwrap();
        assert_eq!(_secrets, vec![secret]);

        fs::remove_file(&db_name).unwrap();
        fs::remove_file("db_file.txt").unwrap();
    }
}
