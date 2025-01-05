//types
use crate::processing::{decryption::*, encryption::*, utils::*};

#[derive(Debug, PartialEq, Clone)]
pub struct Param {
    pub id: String,
    pub ad: String,
    pub salt1: String,
    pub salt2: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secret {
    pub id: String,
    pub message: String
}

//Implement in type Param a constructor and some methods
impl Param{
    //Create data and encrypt the field associated data (or ad) type of Param 
    pub fn new(self, key: &[u8], id: String, ad: String, salt1: String, salt2: String) -> Param{
        let value_encrypted = encrypt_params(key, 
            decode_from_base64(id.clone()).unwrap(),
            ad.as_bytes().to_vec()).unwrap();
        let ad = String::from_utf8(value_encrypted).unwrap();
        Param{id, ad, salt1, salt2}

    }

    //Decrypt the field associated data (ad)
    pub fn decrypt(self, key: &[u8]) -> Vec<u8>{
        let value_decrypted = decrypt_params(key,
            decode_from_base64(self.id).unwrap(),
            self.ad.as_bytes().to_vec()).unwrap();
        value_decrypted
    }
}

//Implement in type secret a constructor and some methods
impl Secret{
    //Create data and encrypt the field message type of Secret 
    pub fn new(self, key: &[u8], ad: &[u8], id: String, message: String) -> Secret{
        let value_encrypted = encrypt_secret(key, 
            decode_from_base64(id.clone()).unwrap(),
            ad,
            message.as_bytes().to_vec()).unwrap();
        let message = String::from_utf8(value_encrypted).unwrap();
        Secret{id, message}
    }
    
    //Encrypt the field message in using ad from type Param and key
    pub fn encrypt(&mut self, key: &[u8], ad: &[u8]) -> &mut Secret{
        let value_encrypted = encrypt_secret(key, 
            decode_from_base64(self.id.clone()).unwrap(),
            ad,
            self.message.as_bytes().to_vec()).unwrap();
        self.message = String::from_utf8(value_encrypted).unwrap();
        self
    }

    //Decrypt the field message in using ad from type Param and key
    pub fn decrypt(self, key: &[u8], ad: &[u8]) -> String{
        let value_decrypted = decrypt_secret(key,
            decode_from_base64(self.id.clone()).unwrap(),
            ad,
            self.message.as_bytes().to_vec()).unwrap();
        String::from_utf8(value_decrypted).unwrap()
    }
}
