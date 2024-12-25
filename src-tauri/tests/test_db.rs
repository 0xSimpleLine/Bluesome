// Unit test for database operations

#[cfg(test)]
mod test_db {
    use bluesome_lib::database::*;
    use std::fs;
    
    #[test]
    fn test_first_opt(){
        let param = Param{
            id: String::from("foo"),
            ad: String::from("foo"),
            salt1: String::from("foo"),
            salt2: String::from("foo")
        };

        let secret = Secret{
            id: String::from("foo"),
            secret: String::from("foo")
        };

        generate_db_name();
        let db_name = read_db_file().unwrap();
        create_db_tables(&db_name, param).unwrap();
        create_secret(&db_name, secret).unwrap();
        fs::remove_file(&db_name).unwrap();
        fs::remove_file("db_file.txt").unwrap();
    }
}
