//types
use crate::processing;
use crate::utils::{decode_from_hex, encode_to_hex};
use base64ct::{Base64, Encoding};

#[derive(Debug, PartialEq, Clone)]
pub struct Param {
    pub id: Vec<u8>,
    pub ad: Vec<u8>,
    pub salt: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParamHex {
    pub id: String,
    pub ad: String,
    pub salt: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secret {
    pub id: String,
    pub title: String,
    pub message: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct User {
    pub username: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct Category {
    pub id: u8,
    pub name: String
}

//Implement in type Param a constructor and some methods
impl Param{
    //Create data and encrypt the field associated data (or ad) type of Param 
    pub fn create(id: Vec<u8>, ad: Vec<u8>, salt: Vec<u8>) -> Param{ Param{id, ad, salt} }

    //Decode field from hex
    pub fn decode(id: String, ad: String, salt: String) -> Param{
        Param{
            id:  decode_from_hex(id).unwrap(),
            ad :  decode_from_hex(ad).unwrap(),
            salt:  decode_from_hex(salt).unwrap(),
        }
    }
}

impl ParamHex{
    pub fn create(id: String, ad: String, salt: String) -> ParamHex{
        ParamHex{id, ad, salt}
    }

    pub fn encode(param: Param) -> ParamHex{
        ParamHex{
            id: encode_to_hex(param.id),
            ad: encode_to_hex(param.ad),
            salt: encode_to_hex(param.salt),
        }
    }
}

//Implement in type secret a constructor and some methods
impl Secret{
    //Create data and encrypt the field message type of Secret 
    pub fn create(key: &[u8], id:Vec<u8>, ad:Vec<u8>, title: String, message: String) -> Secret{
        //Encrypted the message
        let value_encrypted = processing::encrypt_secret(key, 
            &id,
            &ad,
            message.into_bytes()).unwrap();
        let message = Base64::encode_string(&value_encrypted);

        //Encode id "nonce" to hexadecimal
        let id = encode_to_hex(id);
        Secret{id, title, message}
    }

    //Decrypt the field message in using ad from type Param and key
    pub fn decrypt(self, key: &[u8], ad: Vec<u8>) -> String{
        //decrypted the message
        let value_decrypted = processing::decrypt_secret(key,
            decode_from_hex(self.id).unwrap().as_slice(),
            &ad,
            Base64::decode_vec(self.message.as_str()).unwrap()).unwrap();

        //convert the vector to String
        String::from_utf8(value_decrypted).unwrap()
    }
}


