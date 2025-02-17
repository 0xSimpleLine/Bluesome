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
            "CREATE TABLE IF NOT EXISTS param (
                id VARCHAR PRIMARY KEY UNIQUE,
                ad VARCHAR NOT NULL,
                salt1 VARCHAR NOT NULL,
                salt2 VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secret (
                id VARCHAR PRIMARY KEY UNIQUE,
                title VARCHAR,
                message VARCHAR NOT NULL
            );"
        )?;
        tx.commit().unwrap();
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
    pub fn insert_data_secret(&self, secret: Secret) -> Result<()> {
        self.conn.prepare(
            "INSERT INTO secret (id, title, message) VALUES (?1, ?2, ?3)",).unwrap().execute(params![secret.id, 
            secret.title, 
            secret.message])?;
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
        let secret = self.conn.query_row("SELECT title, message FROM secret WHERE id = ?1",
            [id],
            |row| row.get(0))?;
        Ok(secret)
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
