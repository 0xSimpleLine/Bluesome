use argon2::{
    password_hash::{
        rand_core::{OsRng, CryptoRng, RngCore},
    }, Argon2
};

//Generated a slice with size of 32 bytes (256 bit)
fn generate_rng_slice<R>(rng: &mut R) -> Vec<u8>
    where 
        R: CryptoRng + RngCore,
{
    let mut new_random = vec![0u8; 32];
    rng.fill_bytes(&mut new_random);
    new_random
}

//Generated 2 salts in 32 bytes
pub fn generate_salt() -> Vec<u8>{
    let salt = generate_rng_slice(&mut OsRng);
    salt
}

//Derivated Key in Argon2
pub fn derivate_key(password: &[u8], salt: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut output = [0u8; 32];
    Argon2::default().hash_password_into(password, &salt, &mut output).expect("Fail to derivate key");
    Ok(output.to_vec())
}
