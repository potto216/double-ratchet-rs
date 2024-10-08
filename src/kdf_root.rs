use core::convert::TryInto;
use hkdf::Hkdf;
use sha2::Sha512;

#[cfg(test)]
use crate::dh::gen_shared_secret;
use x25519_dalek::SharedSecret;

// the root chain key is the salk and the shared secret is the new key material
// The extract-then-expand paradigm is crucial when dealing with inputs
// like Diffie-Hellman outputs, as it converts potentially structured input
// into a uniformly distributed pseudorandom key. This effectively prevents
//  an attacker from exploiting any inherent properties of the input.

// Abbeviations: rk = root chain key, ck = chain key
pub fn kdf_rk(rk: &[u8; 32], dh_out: &SharedSecret) -> ([u8; 32], [u8; 32]) {
    
    // the extraction step is done here
    let h = Hkdf::<Sha512>::new(Some(rk), dh_out.as_bytes());
    let mut okm = [0u8; 64];
    let info = b"Root Key Info";
    // expands the internal pseudo random key into the new key pair
    h.expand(info, &mut okm).unwrap();
    let (new_rk, new_ck) = okm.split_at(32);
    (
        new_rk.try_into().expect("Incorrect length"),
        new_ck.try_into().expect("Incorrect length"),
    )
}

pub fn kdf_rk_he(rk: &[u8; 32], dh_out: &SharedSecret) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let h = Hkdf::<Sha512>::new(Some(rk), dh_out.as_bytes());
    let mut okm = [0u8; 96];
    let info = b"Root Key Generator";
    h.expand(info, &mut okm).unwrap();
    let (rk, a) = okm.split_at(32);
    let (ck, nhk) = a.split_at(32);
    (
        rk.try_into().expect("Wrong length"),
        ck.try_into().expect("Wrong length"),
        nhk.try_into().expect("Wrong length"),
    )
}

#[cfg(test)]
pub fn gen_ck() -> [u8; 32] {
    let shared_secret = gen_shared_secret();
    let rk = [0; 32];
    let (_, ck) = kdf_rk(&rk, &shared_secret);
    ck
}

#[cfg(test)]
mod tests {
    use crate::dh::gen_shared_secret;
    use crate::kdf_root::kdf_rk;

    #[test]
    fn kdf_root_ratchet() {
        let rk = [0; 32];
        let shared_secret = gen_shared_secret();
        let (rk1, _) = kdf_rk(&rk, &shared_secret);
        let (rk2, _) = kdf_rk(&rk1, &shared_secret);
        assert_ne!(rk1, rk2)
    }
}
