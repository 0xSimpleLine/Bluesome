use argon2::{
    password_hash::{
        rand_core::{OsRng, CryptoRng, RngCore},
            
    }, Argon2
};
use std::{thread, sync::{Arc, mpsc}};

//Generated a slice with size of 32 bytes (256 bit)
fn generate_rng_slice<R>(rng: &mut R) -> [u8; 32]
    where 
        R: CryptoRng + RngCore,
{
    let mut new_random = [0u8; 32];
    rng.fill_bytes(&mut new_random);
    new_random
}

pub fn generate_salts() -> Vec<[u8; 32]>{
    let salt_1 = generate_rng_slice(&mut OsRng);
    let salt_2 = generate_rng_slice(&mut OsRng);
    let salts_final = vec![salt_1, salt_2];
    salts_final
}

pub fn derivate_key(password: &[u8], salt_1: [u8; 32], salt_2: [u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    let (tx, rx) = mpsc::channel();
    let password = Arc::new(password.to_vec());

    //run the task 1
    let tx_1 = tx.clone();
   let password_clone_1 = Arc::clone(&password);
   thread::spawn(move || {
       let mut output = [0u8; 32];
        Argon2::default().hash_password_into(&password_clone_1, &salt_1, &mut output).expect("Fail to derivate key");
        tx_1.send(output).unwrap();
    }).join().unwrap();

    //run the task 2
    let password_clone_2 =  Arc::clone(&password);
    thread::spawn(move || {
       let mut output = [0u8; 32];
        Argon2::default().hash_password_into(&password_clone_2, &salt_2, &mut output).expect("Fail to derivate key");
        tx.send(output).unwrap();
    }).join().unwrap();

    // return all outputs
    let last_output: Vec<[u8; 32]> = rx.iter().collect();
    Ok(last_output)
}
