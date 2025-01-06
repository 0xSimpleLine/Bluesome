//types
use crate::processing::{decryption, encryption};
use crate::utils::{decode_from_hex, encode_to_hex};

#[derive(Debug, PartialEq, Clone)]
pub struct Param {
    pub id: Vec<u8>,
    pub ad: Vec<u8>,
    pub salt1: Vec<u8>,
    pub salt2: Vec<u8>
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secret {
    pub id: String,
    pub message: String
}

//Implement in type Param a constructor and some methods
impl Param{
    //Create data and encrypt the field associated data (or ad) type of Param 
    pub fn create(self, id: Vec<u8>, ad: Vec<u8>, salt1: Vec<u8>, salt2: Vec<u8>) -> Param{
        Param{id, ad, salt1, salt2}
    }

    //Decode field from hex
    pub fn decode_data(self, id: String, ad: String, salt1: String, salt2: String) -> Param{
        Param{
            id:  decode_from_hex(id).unwrap(),
            ad :  decode_from_hex(ad).unwrap(),
            salt1:  decode_from_hex(salt1).unwrap(),
            salt2:  decode_from_hex(salt2).unwrap(),
        }
    }

    //Encrypt AD 
    pub fn encrypt(&mut self, key: &[u8]){
        self.ad = encryption::encrypt_params(key,
            self.id.clone(),
            self.ad.clone()).unwrap();  
    }

    //Decrypt the field associated data (ad)
    pub fn decrypt(self, key: &[u8]) -> Vec<u8>{
        let value_decrypted = decryption::decrypt_params(key,
            self.id,
            self.ad).unwrap();
        value_decrypted
    }
}

//Implement in type secret a constructor and some methods
impl Secret{
    //Create data and encrypt the field message type of Secret 
    pub fn create(self, key: &[u8], ad: Vec<u8>, id: Vec<u8>, message: String) -> Secret{
        //Encrypted the message
        let value_encrypted = encryption::encrypt_secret(key, 
            id.clone(),
            ad,
            message.into_bytes()).unwrap();
        let message = String::from_utf8(value_encrypted).unwrap();

        //Encode id (nonce) to hexadecimal
        let id = encode_to_hex(id);
        Secret{id, message}
    }

    //Decrypt the field message in using ad from type Param and key
    pub fn decrypt(self, key: &[u8], ad: Vec<u8>) -> String{
        //decrypted the message
        let value_decrypted = decryption::decrypt_secret(key,
            decode_from_hex(self.id).unwrap(),
            ad,
            self.message.into_bytes()).unwrap();

        //convert the vector to String
        String::from_utf8(value_decrypted).unwrap()
    }
}
