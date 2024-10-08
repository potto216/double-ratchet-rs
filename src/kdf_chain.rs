use core::convert::TryInto;
use hmac::{Hmac, Mac};
use sha2::Sha512;

#[cfg(test)]
use crate::kdf_root::gen_ck;

type HmacSha512 = Hmac<Sha512>;

// Generates the a pair of keys-a chain key and a message key from a current chain key.
// Abbeviations: mk = message key, ck = chain key
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac_mk = HmacSha512::new_from_slice(ck).expect("Invalid Key Length");
    let mut mac_ck = HmacSha512::new_from_slice(ck).expect("Invalid Key Length");

  // Use separate constants to differentiate the inputs when 
  // generating the message key and the next chain key
  // This ensures that the two keys derived from the same chain key are
  // independent to achieve key separation
    mac_mk.update(&[0x01]); 
    mac_ck.update(&[0x02]);
    // Finalize the HMAC computations
    let result_mk = mac_mk.finalize().into_bytes();
    let result_ck = mac_ck.finalize().into_bytes();
    // Convert the results to [u8; 32]
    let mk = result_mk[..32].try_into().expect("Incorrect Length");
    let next_ck = result_ck[..32].try_into().expect("Incorrect Length");
    (mk, next_ck)
}


#[cfg(test)]
pub fn gen_mk() -> [u8; 32] {
    let ck = gen_ck();
    let (_, mk) = kdf_ck(&ck);
    mk
}

#[cfg(test)]
mod tests {
    use crate::kdf_chain::kdf_ck;
    use crate::kdf_root::gen_ck;
    
    #[test]
    fn kdf_chain_ratchet() {
        let ck = gen_ck();
        let (ck, mk1) = kdf_ck(&ck);
        let (_, mk2) = kdf_ck(&ck);
        assert_ne!(mk1, mk2)
    }
    
}
