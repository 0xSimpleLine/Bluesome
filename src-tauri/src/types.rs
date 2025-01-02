//types
use crate::processing::{decryption, encryption, utils};

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

//Implement in type param a constructor and some methods
impl Param{
    pub fn new(self, key: &[u8], id: String, ad: String, salt1: String, salt2: String) -> Param{
        let value_encrypted = encryption::encrypt_params(key, 
            utils::decode_from_base64(id.clone()).unwrap().as_slice(),
            ad.as_bytes().to_vec()).unwrap();
        let ad = String::from_utf8(value_encrypted).unwrap();
        Param{id, ad, salt1, salt2}

    }
    
    pub fn encrypt(&mut self, key: &[u8]) -> &mut Param{
        let value_encrypted = encryption::encrypt_params(key, 
            self.id.as_bytes(),
            self.ad.as_bytes().to_vec()).unwrap();
        self.ad = String::from_utf8(value_encrypted).unwrap();
        self
    }

    pub fn decrypt(self, key: &[u8]) -> Vec<u8>{
        let value_decrypted = decryption::decrypt_params(key,
            self.id.as_bytes(),
            self.ad.as_bytes().to_vec()).unwrap();
        value_decrypted
    }
}

//Implement in type secret a constructor and some methods
impl Secret{
    pub fn new(self, key: &[u8], ad: &[u8], id: String, message: String) -> Secret{
        let value_encrypted = encryption::encrypt_secret(key, 
            utils::decode_from_base64(id.clone()).unwrap().as_slice(),
            ad,
            message.as_bytes().to_vec()).unwrap();
        let message = String::from_utf8(value_encrypted).unwrap();
        Secret{id, message}

    }
    
    pub fn encrypt(&mut self, key: &[u8], ad: &[u8]) -> &mut Secret{
        let value_encrypted = encryption::encrypt_secret(key, 
            self.id.as_bytes(),
            ad,
            self.message.as_bytes().to_vec()).unwrap();
        self.message = String::from_utf8(value_encrypted).unwrap();
        self
    }

    pub fn decrypt(self, key: &[u8], ad: &[u8]) -> String{
        let value_decrypted = decryption::decrypt_secret(key,
            self.id.as_bytes(),
            ad,
            self.message.as_bytes().to_vec()).unwrap();
        String::from_utf8(value_decrypted).unwrap()
    }
}
