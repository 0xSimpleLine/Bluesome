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
            title: String::from("foo"), 
            message: String::from("foo")
        };

        let mut _secret = Secret{
            id: String::from("bar"),
            title: String::from("bar"), 
            message: String::from("bar")
        };

        generate_db_name().unwrap();
        let db_name = read_db_file("db_file.txt").unwrap();

        let mut db = DBManager::open(&db_name).unwrap();
        db.create_tables().unwrap();
        db.insert_data_param(param.clone()).unwrap();
        db.insert_data_secret(secret.clone()).unwrap();
        db.insert_data_secret(_secret.clone()).unwrap();

        let secrets = db.read_all_secrets().unwrap();
        let secret_ = db.read_secret( "foo").unwrap();

        assert_eq!(secrets, vec![secret.clone(), _secret.clone()]);
        assert_eq!(secret_, secret.message);

        _secret.message = "foo".to_string();
        _secret.title = "foo".to_string();
        db.update_secret(secret.clone()).unwrap();
        assert_eq!(_secret.title, "foo".to_string());
        assert_eq!(_secret.message, "foo".to_string());

        db.remove_secret(_secret.id.clone()).unwrap();
        let _secrets = db.read_all_secrets().unwrap();
        assert_eq!(_secrets, vec![secret]);
        db.conn.close().unwrap();

        fs::remove_file(&db_name).unwrap();
        fs::remove_file("db_file.txt").unwrap();
    }
}
