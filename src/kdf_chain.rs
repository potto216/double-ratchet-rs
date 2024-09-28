use core::convert::TryInto;
use hmac::{Hmac, Mac};
use sha2::Sha512;

#[cfg(test)]
use crate::kdf_root::gen_ck;

type HmacSha512 = Hmac<Sha512>;

pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mac = HmacSha512::new_from_slice(ck).expect("Invalid Key Length");
    let result = mac.finalize().into_bytes();
    let (a, b) = result.split_at(32);

    (
        a.try_into().expect("Incorrect Length"),
        b.try_into().expect("Incorrect Length"),
    )
}

pub fn kdf_ck_v2(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Create HMAC instances with ck as the key
    let mut mac1 = HmacSha512::new_from_slice(ck).expect("Invalid Key Length");
    let mut mac2 = HmacSha512::new_from_slice(ck).expect("Invalid Key Length");

    // Use separate constants as input
    mac1.update(&[0x01]);
    mac2.update(&[0x02]);

    // Finalize the HMAC computations
    let result1 = mac1.finalize().into_bytes();
    let result2 = mac2.finalize().into_bytes();

    // Convert the results to [u8; 32]
    let mk = result1[..32].try_into().expect("Incorrect Length");
    let next_ck = result2[..32].try_into().expect("Incorrect Length");

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
    use crate::kdf_chain::kdf_ck_v2;
    use crate::kdf_root::gen_ck;
    
    #[test]
    fn kdf_chain_ratchet() {
        let ck = gen_ck();
        let (ck, mk1) = kdf_ck(&ck);
        let (_, mk2) = kdf_ck(&ck);
        assert_ne!(mk1, mk2)
    }
    
    #[test]
    fn kdf_chain_ratchet_v2() {
        let ck = gen_ck();
        let (ck, mk1) = kdf_ck_v2(&ck);
        let (_, mk2) = kdf_ck_v2(&ck);
        assert_ne!(mk1, mk2)
    }
}
