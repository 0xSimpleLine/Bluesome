use hex_literal::hex;

const KEY : [u8;32] = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
const AD : [u8;32] = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");

#[cfg(test)]
mod test_types{
    use super::*;
    use bluesome_lib::types::*;
    use bluesome_lib::processing::encrypt::generate_nonce;
    
    //Test method and constructor for Param type
    #[test]
    fn test_param_test{
        let nonce = generate_nonce();
        Param::new(KEY, nonce);
    }
}
