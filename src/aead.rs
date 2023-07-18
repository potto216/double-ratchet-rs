use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use alloc::vec::Vec;
use rand_core::{OsRng, RngCore};

pub fn encrypt(mk: &[u8; 32], data: &[u8], associated_data: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let cipher = Aes256GcmSiv::new_from_slice(mk).expect("Encryption failure {}");

    let mut nonce_data = [0u8; 12];
    OsRng::fill_bytes(&mut OsRng, &mut nonce_data);
    let nonce = Nonce::from_slice(&nonce_data);

    let mut buffer = Vec::new();
    buffer.extend_from_slice(data);

    cipher
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("Encryption failure {}");

    (buffer, nonce_data)
}

pub fn decrypt(
    mk: &[u8; 32],
    enc_data: &[u8],
    associated_data: &[u8],
    nonce: &[u8; 12],
) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(mk).expect("Decryption failure {}");

    let nonce = Nonce::from_slice(nonce);

    let mut buffer = Vec::new();
    buffer.extend_from_slice(enc_data);

    cipher
        .decrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("Decryption failure {}");

    buffer
}

#[cfg(test)]
mod tests {
    use crate::aead::{decrypt, encrypt};
    use crate::kdf_chain::gen_mk;

    #[test]
    fn enc_a_dec() {
        let test_data = include_bytes!("aead.rs");
        let associated_data = include_bytes!("lib.rs");
        let mk = gen_mk();
        let (enc_data, nonce) = encrypt(&mk, test_data, associated_data);
        let data = decrypt(&mk, &enc_data, associated_data, &nonce);
        assert_eq!(test_data, data.as_slice())
    }
}
