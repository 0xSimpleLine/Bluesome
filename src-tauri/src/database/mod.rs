use rusqlite::{Connection, Result};
use argon2::password_hash::rand_core::OsRng;
use crate::auth::key_derivation::generate_rng_slice;
use std::{fs::File, io::prelude::*, str};

//types
pub struct Param {
    id: String,
    ad: String,
    salt1: String,
    salt2: String
}

pub struct Secret {
    id: String,
    secret: String
}

//This function generate a random slice and stock the name in file txt
pub fn generate_db_name() -> Result<(), String>{
    let db_name = generate_rng_slice(&mut OsRng);
    //Create database
    let mut file = File::create("db_file.txt")
        .expect("Error: Impossible to create file");
    //Write in databse
    file.write_all(&db_name)
        .expect("Error: Impossible to write in file");
    Ok(())
}

//Read DB File
pub fn read_db() -> Result<String, String>{
    let mut file = File::open("db_file.txt")
        .expect("Error: Impossible to find file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Error: Impossible to read file");
    Ok(contents)
}

//Connect to database or create new database
pub fn connection(path: &str) -> Result<Connection, String> {
  let db = Connection::open(path).expect("Error: Impossible to connect in database");  
  Ok(db)
}

//create db and tables 
pub fn create_db_tables(path: &str, param: Param) -> Result<(), String> {
    let conn = connection(path).unwrap();
    conn.execute_batch(
        "BEGIN;
        CREATE TABLE params (
            id VARCHAR PRIMARY KEY,
            ad VARCHAR NOT NULL,
            salt1 VARCHAR NOT NULL
            salt2 VARCHAR NOT NULL
        );
        CREATE TABLE secret (
            id VARCHAR PRIMARY KEY,
            secret VARCHAR NOT NULL
        );
        COMMIT;"
    ).expect("Error: Impossible to create tables");

    conn.execute(
        "INSERT INTO params (id, ad, salt1, salt2) VALUES (?1, ?2, ?3, ?4)",
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
