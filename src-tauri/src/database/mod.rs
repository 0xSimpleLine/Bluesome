use rusqlite::{Connection, Result, Error};
use std::{fs, str};
use sha2::{Sha256, Digest};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use crate::auth::utils::encode_to_hex;
use crate::types::*;

fn hash_db_name(rng: &[u8]) -> String {
    let hasher = Sha256::digest(rng);
    return encode_to_hex(hasher[..10].to_vec());
}

//This function generate a random slice and stock the name in file txt
pub fn generate_db_name() -> Result<(), String>{
    //Generate a random data
    let mut rand_slice = [0u8; 16];
    OsRng.fill_bytes(&mut rand_slice);
    let mut db_name = hash_db_name(&rand_slice); 
    db_name.push_str(".sqlite3");

    //Create file "file.txt" and write databse
    fs::write("db_file.txt", db_name)
        .expect("Impossible to write in file");
    Ok(())
}

//Read DB File and return his content
pub fn read_db_file() -> Result<String, String>{
    let content = fs::read_to_string("db_file.txt")
        .expect("Impossible to read file");
    Ok(content)
}

//get the content of db file to connect to database or create new database if don't exist
fn connection(path: &str) -> Result<Connection, String> {
  let db = Connection::open(path).expect("Impossible to connect in database");  Ok(db)
}

//create db, tables and insert data for table param
pub fn create_db_tables(path: &str, param: Param) -> Result<(), String> {
    //Create db if don't exist
    let conn = connection(path).unwrap();

    //Run command to create table 
    conn.execute_batch(
        "BEGIN;
        CREATE TABLE param (
            id VARCHAR PRIMARY KEY UNIQUE,
            ad VARCHAR NOT NULL,
            salt1 VARCHAR NOT NULL,
            salt2 VARCHAR NOT NULL
        );
        CREATE TABLE secret (
            id VARCHAR PRIMARY KEY UNIQUE,
            message VARCHAR NOT NULL
        );
        COMMIT;"
    ).expect("Impossible to create tables");

    //Insert data into table param
    conn.execute(
        "INSERT INTO param (id, ad, salt1, salt2) VALUES (?1, ?2, ?3, ?4)",
        (param.id, param.ad, param.salt1, param.salt2),
    ).expect("Impossible to stock data");
    conn.close().unwrap();
    Ok(())
}

//Insert data in table secret
pub fn create_new_secret(path: &str, secret: Secret) -> Result<(), String> {
    let conn = connection(path).unwrap();
    conn.execute(
        "INSERT INTO secret (id, message) VALUES (?1, ?2)",
        (secret.id, secret.message)
    ).expect("Impossible to stock secret");
    conn.close().unwrap();
    Ok(())
}

//Read all data from table secret
pub fn read_all_secrets(path: &str) -> Result<Vec<Secret>, Error> {
    let conn = connection(path).unwrap();
    let mut stmt = conn.prepare("SELECT id, message FROM secret")
        .expect("Impossible to read all secrets");
    let rows = stmt.query_map([], |row| {
        Ok(Secret {
            id: row.get(0)?,
            message: row.get(1)?
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
    let secret = conn.query_row("SELECT message FROM secret WHERE id = ?1",
        [id],
        |row| row.get(0)).expect("Impossible to read secret");
    conn.close().unwrap();
    Ok(secret)
}

//Modify one data from table secret
pub fn update_secret(path: &str, secret: Secret) -> Result<(), String>{
    let conn = connection(path).unwrap();
    conn.execute("UPDATE secret SET message = ?1 WHERE id = ?2", 
        [secret.message, secret.id]).expect("Impossible to modify this secret");
    conn.close().unwrap();
    Ok(())
}

//Delete one data from table secret
pub fn remove_secret(path: &str, id: String) -> Result<(), String>{
    let conn = connection(path).unwrap();
    conn.execute("DELETE FROM secret WHERE id = ?1", [id])
        .expect("Impossible to delete this secret");
    conn.close().unwrap();
    Ok(())
}
