use rusqlite::{Connection, Result, Error, params};
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
pub fn generate_db_name() -> Result<(), String> {
    //Generate a random data
    let mut rand_slice = [0u8; 16];
    OsRng.fill_bytes(&mut rand_slice);
    let mut db_name = hash_db_name(&rand_slice); 
    db_name.push_str(".sqlite3");
    generate_file("db_file.txt", db_name).unwrap();
    return Ok(());
}

//Read DB file and return his content
pub fn read_db_file() -> Result<String, String>{
    let content = fs::read_to_string("db_file.txt")
        .expect("Impossible to read file");
    Ok(content)
}

//get the content of db file to connect to database or create new database if don't exist
fn connection(path: &str) -> Result<Connection, String> {
  let db = Connection::open(path).expect("Impossible to connect in database");  
  db.execute_batch("
        PRAGMA synchronous = FULL;
        PRAGMA journal_mode = WAL;
        PRAGMA temp_store = MEMORY;
      ").unwrap();
  Ok(db)
}

//create db, tables and insert data for table param
pub fn create_db_tables(path: &str) -> Result<(), String> {
    let mut conn = connection(path).unwrap();
    let tx = conn.transaction().unwrap();

    //Run request to create table 
    tx.execute_batch(
        "CREATE TABLE param (
            id VARCHAR PRIMARY KEY UNIQUE,
            ad VARCHAR NOT NULL,
            salt1 VARCHAR NOT NULL,
            salt2 VARCHAR NOT NULL
        );

        CREATE TABLE secret (
            id VARCHAR PRIMARY KEY UNIQUE,
            title VARCHAR,
            message VARCHAR NOT NULL
        );"
    ).expect("Impossible to create tables");
    tx.commit().unwrap();
    Ok(())
}

//Insert data in table Param
pub fn insert_data_param(path: &str, param: Param) -> Result<(), String>{
    let conn = connection(path).unwrap();
    //encode the param data
    let id = encode_to_hex(param.id);
    let ad = encode_to_hex(param.ad);
    let salt1 = encode_to_hex(param.salt1);
    let salt2 = encode_to_hex(param.salt2);

    //Insert data into table param
    conn.prepare(
        "INSERT INTO param (id, ad, salt1, salt2) VALUES (?1, ?2, ?3, ?4)",
    ).unwrap().execute(params![id, ad, salt1, salt2]).expect("Impossible to insert data");
    Ok(())
}

//Insert data in table Secret
pub fn insert_new_secret(path: &str, secret: Secret) -> Result<(), String> {
    let conn = connection(path).unwrap();
    conn.execute(
        "INSERT INTO secret (id, title, message) VALUES (?1, ?2, ?3)",
        (secret.id, secret.title, secret.message)
    ).expect("Impossible to insert data");
    Ok(())
}

//Read all data from table secret
pub fn read_all_secrets(path: &str) -> Result<Vec<Secret>, Error> {
    let conn = connection(path).unwrap();
    let mut stmt = conn.prepare("SELECT id, title, message FROM secret")
        .expect("Impossible to read all secrets");
    let rows = stmt.query_map([], |row| {
        Ok(Secret {
            id: row.get(0)?,
            title: row.get(1)?,
            message: row.get(2)?
        })})?;
    let mut messages: Vec<Secret> = Vec::new();
    for row in rows{
        messages.push(row?);
    }
    stmt.finalize().unwrap();
    Ok(messages)
}

//Read one data from table secret 
pub fn read_secret(path: &str, id: &str) -> Result<String, String>{
    let conn = connection(path).unwrap();
    let secret = conn.query_row("SELECT title, message FROM secret WHERE id = ?1",
        [id],
        |row| row.get(0)).expect("Impossible to read secret");
    Ok(secret)
}

//Modify one data from table secret
pub fn update_secret(path: &str, secret: Secret) -> Result<(), String>{
    let conn = connection(path).unwrap();
    conn.execute("UPDATE secret SET title = ?1, message = ?2 WHERE id = ?3", 
        [secret.title, secret.message, secret.id]).expect("Impossible to modify this secret");
    Ok(())
}

//Delete one data from table secret
pub fn remove_secret(path: &str, id: String) -> Result<(), String>{
    let conn = connection(path).unwrap();
    conn.execute("DELETE FROM secret WHERE id = ?1", [id])
        .expect("Impossible to delete this secret");
    Ok(())
}

/*
pub fn close(self) -> Result<(), String>{
    self.conn.execute_batch("
        ANALYSE;
        PRAGMA optimize;
        ").expect("Impossible to close the connection");
} */
