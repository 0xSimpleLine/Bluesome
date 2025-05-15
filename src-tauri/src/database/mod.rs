use rusqlite::{Connection, Result, params};
use std::{fs, str};
use sha2::{Sha256, Digest};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use crate::utils::{encode_to_hex, generate_file};
use crate::types::*;

//Hash a random value and convert to hex
fn hash_db_name(rng: &[u8]) -> String {
    let hasher = Sha256::digest(rng);
    return encode_to_hex(hasher[..10].to_vec());
}

//Genereate one file and include the db name
pub fn generate_db_name() -> Result<()> {
    //Generate a random data
    let mut rand_slice = [0u8; 16];
    OsRng.fill_bytes(&mut rand_slice);
    let mut db_name = hash_db_name(&rand_slice); 
    db_name.push_str(".sqlite3");
    generate_file("db_file.txt", db_name).unwrap();
    return Ok(());
}

//Read DB file and return his content
pub fn read_db_file(path: &str) -> Result<String> {
    let content = fs::read_to_string(path).unwrap();
    Ok(content)
}

//Connection type
pub struct DBManager{
    pub conn: Connection
}

impl DBManager{

    //get the content of db file to connect to database or create new database if don't exist
    pub fn open(path: &str) -> Result<DBManager> {
      let db = Connection::open(path)?;  
      db.execute_batch("
            PRAGMA synchronous = NORMAL;
            PRAGMA journal_mode = WAL;
            PRAGMA temp_store = DEFAULT;
          ").unwrap();
      Ok(DBManager{conn:db})
    }

    //create tables  Param and Secret
    pub fn create_tables(&mut self) -> Result<()> {
        let tx = self.conn.transaction().unwrap();

        //Run request to create table 
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY,
                username VARCHAR NOT NULL UNIQUE
            );
            
            CREATE TABLE IF NOT EXISTS category (
                id INTEGER PRIMARY KEY,
                name VARCHAR NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS param (
                id VARCHAR PRIMARY KEY UNIQUE,
                ad VARCHAR NOT NULL,
                salt1 VARCHAR NOT NULL,
                salt2 VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secret (
                id VARCHAR PRIMARY KEY UNIQUE,
                category_id INTEGER not null,
                title VARCHAR NOT NULL,
                message VARCHAR NOT NULL,
                note TEXT,
                FOREIGN KEY (category_id) REFERENCES category(id)
            );"
        )?;
        tx.commit().unwrap();
        Ok(())
    }

    //Insert data in table User
    pub fn insert_data_user(&self, user: User) -> Result<()>{
        //Insert data into table param
        self.conn.prepare(
            "INSERT INTO user (username) VALUES (?1)",)
            .unwrap().execute(params![user.username])?;
        Ok(())
    }

    pub fn update_user(&self, user: User) -> Result<()> {
        self.conn.execute("UPDATE user SET username = ?1 WHERE id = 1",
            [user.username])?;
        Ok(())
    }

    pub fn read_user_data(&self) -> Result<String>{
        self.conn.query_row("SELECT * FROM user WHERE id = 1", 
            [],
            |row| row.get(1))
    }

    //Insert data in table Categorie
    pub fn insert_data_category(&self, category: Category) -> Result<()>{
        //Insert data into table param
        self.conn.prepare(
            "INSERT INTO category (name) VALUES (?1)",)
            .unwrap().execute(params![category.name])?;
        Ok(())
    }

    pub fn read_all_categories(&self) -> Result<Vec<Category>>{
        let mut stmt = self.conn.prepare("SELECT id, name FROM category")
            .expect("Impossible to read all categories");
        let rows = stmt.query_map([], |row| {
            Ok(Category {
                id: row.get(0)?,
                name: row.get(1)?
            })})?;
        let mut categories = vec![];
        for row in rows{
            categories.push(row?);
        }
        Ok(categories)
    }

    pub fn find_category(&self, id: u8) -> Result<String>{
        self.conn.query_row("SELECT name from Category where id = ?1",
            [id], |row| row.get(0)) 
    }

    pub fn update_category(&self, category: Category) -> Result<()>{
        self.conn.execute("UPDATE category SET name = ?1 where id = ?2", 
            params![category.name, category.id])?;
        Ok(())
    }

    pub fn remove_category(&self, id: u8) -> Result<()>{
        self.conn.execute("DELETE from category where id = ?1", 
            [id])?;
        Ok(())
    }

    //Insert data in table Param
    pub fn insert_data_param(&self, param_hex: ParamHex) -> Result<()>{
        //Insert data into table param
        self.conn.prepare(
            "INSERT INTO param (id, ad, salt1, salt2) VALUES (?1, ?2, ?3, ?4)",).unwrap().execute(params![param_hex.id, 
            param_hex.ad, 
            param_hex.salt1,
            param_hex.salt2])?;
        Ok(())
    }

    //Insert data in table Secret
    pub fn insert_data_secret(&self, secret: Secret, category: Category) -> Result<()> {
        self.conn.prepare(
            "INSERT INTO secret (id, title, message, category_id) VALUES (?1, ?2, ?3, ?4)",).unwrap().execute(params![secret.id, 
            secret.title, 
            secret.message,
            category.id])?;
        Ok(())
    }

    //Read all data from table secret
    pub fn read_all_secrets(&self) -> Result<Vec<Secret>> {
        let mut stmt = self.conn.prepare("SELECT id, title, message FROM secret")
            .expect("Impossible to read all secrets");
        let rows = stmt.query_map([], |row| {
            Ok(Secret {
                id: row.get(0)?,
                title: row.get(1)?,
                message: row.get(2)?
            })})?;
        let mut messages = vec![];
        for row in rows{
            messages.push(row?);
        }
        Ok(messages)
    }

    //Read one data from table secret 
    pub fn read_secret(&self, id: &str) -> Result<String>{
        self.conn.query_row("SELECT title, message FROM secret WHERE id = ?1",
            [id],
            |row| row.get(0))
    }

    //Modify one data from table secret
    pub fn update_secret(&self, secret: Secret) -> Result<()>{
        self.conn.execute("UPDATE secret SET title = ?1, message = ?2 WHERE id = ?3", 
            [secret.title, secret.message, secret.id])?;
        Ok(())
    }

    //Delete one data from table secret
    pub fn remove_secret(&self, id: String) -> Result<()>{
        self.conn.execute("DELETE FROM secret WHERE id = ?1", [id])?;
        Ok(())
    }
}
