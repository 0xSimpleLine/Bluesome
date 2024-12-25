use rusqlite::{Connection, Result};
use std::{fs, str};
use sha2::{Sha256, Digest};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use crate::auth::utils::encode_to_hex;

//types
pub struct Param {
    pub id: String,
    pub ad: String,
    pub salt1: String,
    pub salt2: String
}

pub struct Secret {
    pub id: String,
    pub secret: String
}

fn hash_db_name(rng: &[u8]) -> String {
    let hasher = Sha256::digest(rng);
    return encode_to_hex(hasher.to_vec());
}

//This function generate a random slice and stock the name in file txt
pub fn generate_db_name() -> Result<(), String>{
    let mut rand_slice = [0u8; 16];
    OsRng.fill_bytes(&mut rand_slice);
    let db_name = hash_db_name(&rand_slice); 

    //Create file "file.txt" and write databse
    fs::write("db_file.txt", db_name)
        .expect("Error: Impossible to write in file");
    Ok(())
}

//Read DB File
pub fn read_db_file() -> Result<String, String>{
    let content = fs::read_to_string("db_file.txt")
        .expect("Error: Impossible to read file");
    Ok(content)
}

//Connect to database or create new database
fn connection(path: &str) -> Result<Connection, String> {
  let db = Connection::open(path).expect("Error: Impossible to connect in database");  
  Ok(db)
}

//create db and tables 
pub fn create_db_tables(path: &str, param: Param) -> Result<(), String> {
    let conn = connection(path).unwrap();
    conn.execute_batch(
        "BEGIN;
        CREATE TABLE param (
            id VARCHAR PRIMARY KEY,
            ad VARCHAR NOT NULL,
            salt1 VARCHAR NOT NULL,
            salt2 VARCHAR NOT NULL
        );
        CREATE TABLE secret (
            id VARCHAR PRIMARY KEY,
            secret VARCHAR NOT NULL
        );
        COMMIT;"
    ).expect("Error: Impossible to create tables");

    conn.execute(
        "INSERT INTO param (id, ad, salt1, salt2) VALUES (?1, ?2, ?3, ?4)",
        (param.id, param.ad, param.salt1, param.salt2),
    ).expect("Error: Impossible to stock data");
    
    Ok(())
}

pub fn create_secret(path: &str, secret: Secret) -> Result<(), String> {
    let conn = connection(path).unwrap();
    conn.execute(
        "INSERT INTO secret (id, secret) VALUES (?1, ?2)",
        (secret.id, secret.secret)
    ).expect("Error: Impossible to stock data");
    Ok(())
}
