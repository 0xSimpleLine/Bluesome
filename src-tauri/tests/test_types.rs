use hex_literal::hex;
use bluesome_lib::utils::encode_to_hex;

const KEY : [u8;32] = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

#[cfg(test)]
mod test_types{
    use super::*;
    use bluesome_lib::types::*;
    use bluesome_lib::processing::encryption::{generate_nonce, generate_ad};
    use bluesome_lib::auth::key_derivation::generate_salts;
    
    //Test method and constructor for Param type
    #[test]
    fn test_param(){
        // Generate Nonce
        let nonce = generate_nonce();
        let nonce_hex = encode_to_hex(nonce.clone());
        // Generate salts
        let salts = generate_salts();
        let salts_hex = (encode_to_hex(salts[0].clone()), encode_to_hex(salts[1].clone()));
        let ad = generate_ad();
        let ad_hex = encode_to_hex(ad.clone());

        //Verify if the fields are decode to hexadecimal
        let param_decoded = Param::decode(nonce_hex.clone(), ad_hex, salts_hex.0.clone(), salts_hex.1.clone());
        assert_eq!(nonce, param_decoded.id);
        assert_eq!(ad, param_decoded.ad);
        assert_eq!(salts[0], param_decoded.salt1);
        assert_eq!(salts[1], param_decoded.salt2);
    }

    //Test method and constructor for Secret type
    #[test]
    fn test_secret(){
        let nonce = generate_nonce();
        let ad = generate_ad();
        let plaint_text = String::from("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let secret = Secret::create(&KEY, nonce, ad.clone(), String::from("test"), plaint_text.clone());
        
        //Verify if message has been encrypted
        assert_ne!(plaint_text, secret.message);

        //Verify if message is same that the text origin
        assert_eq!(plaint_text, secret.decrypt(&KEY, ad));
    }
}
