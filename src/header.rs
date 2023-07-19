//! Message header.

use crate::aead::encrypt;
use crate::dh::DhKeyPair;
use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Serialize, Deserialize, Debug, Zeroize, Clone, PartialEq, Eq)]
#[zeroize(drop)]
pub struct Header {
    ad: Vec<u8>,
    pub public_key: PublicKey,
    pub pn: usize,
    pub n: usize,
}

// A message header.
impl Header {
    /// Create a new message header.
    /// Requires a [DhKeyPair], previous chain length, and message number.
    /// Returns a [Header].
    pub fn new(dh_pair: &DhKeyPair, pn: usize, n: usize) -> Self {
        Header {
            ad: Vec::new(),
            public_key: dh_pair.public_key,
            pn,
            n,
        }
    }

    pub fn concat(&self, ad: &[u8]) -> Vec<u8> {
        let mut header = self.clone();
        header.ad = ad.to_vec();
        postcard::to_allocvec(&header).expect("Failed to serialize Header")
    }

    pub fn encrypt(&self, hk: &[u8; 32], ad: &[u8]) -> EncryptedHeader {
        let header_data = self.concat(ad);
        let enc_header = encrypt(hk, &header_data, b"");
        EncryptedHeader(enc_header.0, enc_header.1)
    }
}

impl From<Vec<u8>> for Header {
    fn from(d: Vec<u8>) -> Self {
        postcard::from_bytes(&d).unwrap()
    }
}

impl From<&[u8]> for Header {
    fn from(d: &[u8]) -> Self {
        postcard::from_bytes(d).unwrap()
    }
}

impl From<Header> for Vec<u8> {
    fn from(s: Header) -> Self {
        s.concat(b"")
    }
}

pub struct EncryptedHeader(Vec<u8>, [u8; 12]);

impl EncryptedHeader {
    pub fn decrypt(&self, hk: &Option<[u8; 32]>) -> Option<Header> {
        let key_d = match hk {
            None => return None,
            Some(d) => d,
        };

        let cipher = match Aes256GcmSiv::new_from_slice(key_d) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let nonce = Nonce::from_slice(&self.1);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.0);
        match cipher.decrypt_in_place(nonce, b"", &mut buffer) {
            Ok(_) => {}
            Err(_) => return None,
        };
        Some(Header::from(buffer))
    }
}

#[cfg(test)]
pub fn gen_header() -> Header {
    let dh_pair = DhKeyPair::new();
    let pn = 10;
    let n = 50;
    Header::new(&dh_pair, pn, n)
}

#[cfg(test)]
mod tests {
    use x25519_dalek::PublicKey;

    use crate::aead::{decrypt, encrypt};
    use crate::header::{gen_header, Header};
    use crate::kdf_chain::gen_mk;

    #[test]
    fn ser_des() {
        let ad = b"";
        let header = gen_header();
        let serialized = header.concat(ad);
        let created = Header::from(serialized.as_slice());
        assert_eq!(header, created)
    }

    #[test]
    fn enc_header() {
        let header = gen_header();
        let mk = gen_mk();
        let header_data = header.concat(b"");
        let data = include_bytes!("aead.rs");
        let (encrypted, nonce) = encrypt(&mk, data, &header_data);
        let decrypted = decrypt(&mk, &encrypted, &header_data, &nonce);
        assert_eq!(decrypted, data.to_vec())
    }

    #[test]
    fn test_eq_header() {
        let header1 = gen_header();
        let header2 = gen_header();
        assert_ne!(header1, header2)
    }

    #[test]
    fn debug_header() {
        let header = gen_header();
        let _string = alloc::format!("{:?}", header);
    }

    #[test]
    fn gen_ex_header() {
        let ex_header = Header {
            ad: alloc::vec![0],
            public_key: PublicKey::from([1; 32]),
            pn: 0,
            n: 0,
        };
        let _string = alloc::format!("{:?}", ex_header);
    }

    #[test]
    fn dec_header() {
        let header = gen_header();
        let encrypted = header.encrypt(&[0; 32], &[0]);
        let decrypted = encrypted.decrypt(&Some([1u8; 32]));
        assert_eq!(None, decrypted)
    }
}
