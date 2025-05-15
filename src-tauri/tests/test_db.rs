// Unit test for database operations

#[cfg(test)]
mod test_db {
    use bluesome_lib::{database::*, types::*};
    use std::fs;
   
    #[test]
    fn test_first_opt(){
        let param_hex = ParamHex{
            id: String::from("foo").into(),
            ad: String::from("foo").into(),
            salt: String::from("foo").into(),
        };

        let mut user = User{
            username: String::from("foo")
        };

        let category = Category{
            id: 1,
            name: String::from("foo")
        };

        let mut _category = Category{
            id: 2,
            name: String::from("bar")
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

        //Init database
        generate_db_name().unwrap();
        let db_name = read_db_file("db_file.txt").unwrap();
        let mut db = DBManager::open(&db_name).unwrap();
        db.create_tables().unwrap();
        db.insert_data_user(user.clone()).unwrap();
        db.insert_data_category(category.clone()).unwrap();
        db.insert_data_category(_category.clone()).unwrap();
        db.insert_data_param(param_hex).unwrap();
        db.insert_data_secret(secret.clone(), category.clone()).unwrap();
        db.insert_data_secret(_secret.clone(), category.clone()).unwrap();


        //Read datas
        let secrets = db.read_all_secrets().unwrap();
        let secret_ = db.read_secret("foo").unwrap();
        assert_eq!(secrets, vec![secret.clone(), _secret.clone()]);
        assert_eq!(secret_, secret.message);

        let user_ = db.read_user_data().unwrap();
        assert_eq!(user_, "foo".to_string());

        let category_ = db.find_category(category.id).unwrap();
        let categories = db.read_all_categories().unwrap();
        assert_eq!(category_, category.name);
        assert_eq!(vec![category.clone(), _category.clone()], categories);


        //update datas
        user.username = "bar".to_string();
        db.update_user(user.clone()).unwrap();
        let user_ = db.read_user_data().unwrap();
        assert_eq!(user.username, user_);
        
        _category.name = "foobar".to_string();
        db.update_category(_category.clone()).unwrap();
        let category_ = db.find_category(_category.id).unwrap();
        assert_eq!(_category.name, category_);

        _secret.message = "foo".to_string();
        _secret.title = "foo".to_string();
        db.update_secret(_secret.clone()).unwrap();
        let secrets_ = db.read_all_secrets().unwrap();
        assert_eq!(vec![secret.clone(), _secret.clone()], secrets_);

        //Delete Data
        db.remove_category(_category.id).unwrap();
        let categories = db.read_all_categories().unwrap();
        assert_eq!(vec![category], categories);    

        db.remove_secret(_secret.id.clone()).unwrap();
        let _secrets = db.read_all_secrets().unwrap();
        assert_eq!(vec![secret], _secrets);

        db.conn.close().unwrap();


        //others there're not tests
        fs::remove_file(&db_name).unwrap();
        //fs::remove_file(format!("{:?}-shm", db_name)).unwrap();
        //fs::remove_file(format!("{:?}-wal", db_name)).unwrap();
        fs::remove_file("db_file.txt").unwrap();
    }
}
