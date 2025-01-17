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

        // Create data with type 
        let mut param = Param::create(nonce.clone(), ad.to_vec(), salts[0].clone(), salts[1].clone());
        param.encrypt(&KEY);
        //Verify if ad is encrypted correctly
        assert_ne!(ad, param.ad);

        //Verify if ad is decrypted correctly
        assert_eq!(ad, param.decrypt(&KEY));

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
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        let salts = generate_salts();
        let plaint_text = String::from("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let ad = generate_ad();
        let _param = Param::create(nonce1.clone(), ad.clone(), salts[0].clone(), salts[1].clone());
        let secret = Secret::create(&KEY, ad.clone(), nonce2, plaint_text.clone());
        
        //Verify if message has been encrypted
        assert_ne!(plaint_text, secret.message);

        //Verify if message is same that the text origin
        assert_eq!(secret.decrypt(&KEY, ad), plaint_text);
    }
}
