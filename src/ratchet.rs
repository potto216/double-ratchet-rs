//! Ratchet providing encryption and decryption.

use crate::aead::{decrypt, encrypt};
use crate::dh::DhKeyPair;
use crate::header::{Header, EncryptedHeader};
use crate::kdf_chain::kdf_ck;
use crate::kdf_root::{kdf_rk, kdf_rk_he};
use alloc::vec::Vec;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

const MAX_SKIP: usize = 100;

/// A standard ratchet.
#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct Ratchet {
    dhs: DhKeyPair,
    dhr: Option<PublicKey>,
    rk: [u8; 32],
    ckr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ns: usize,
    nr: usize,
    pn: usize,
    mkskipped: HashMap<([u8; 32], usize), [u8; 32]>,
}

impl Zeroize for Ratchet {
    fn zeroize(&mut self) {
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        self.mkskipped.clear();
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Ratchet {
    /// Initialize a [Ratchet] with a remote [PublicKey]. Initialized second.
    /// Requires a shared key and a [PublicKey].
    /// Returns a [Ratchet].
    pub fn init_alice(sk: [u8; 32], bob_dh_public_key: PublicKey) -> Self {
        let dhs = DhKeyPair::new();
        let (rk, cks) = kdf_rk(&sk, &dhs.key_agreement(&bob_dh_public_key));
        Ratchet {
            dhs,
            dhr: Some(bob_dh_public_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    /// Initialize a [Ratchet] without a remote [PublicKey]. Initialized first.
    /// Requires a shared key.
    /// Returns a [Ratchet] and a [PublicKey].
    pub fn init_bob(sk: [u8; 32]) -> (Self, PublicKey) {
        let dhs = DhKeyPair::new();
        let public_key = dhs.public_key;
        let ratchet = Ratchet {
            dhs,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };
        (ratchet, public_key)
    }

    /// Encrypt bytes with a [Ratchet].
    /// Requires bytes and associated bytes.
    /// Returns a [Header], encrypted bytes, and a nonce.
    pub fn encrypt(&mut self, data: &[u8], associated_data: &[u8]) -> (Header, Vec<u8>, [u8; 12]) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        self.ns += 1;
        let (encrypted_data, nonce) = encrypt(&mk, data, &header.concat(associated_data));
        (header, encrypted_data, nonce)
    }

    fn try_skipped_message_keys(
        &mut self,
        header: &Header,
        enc_data: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Option<Vec<u8>> {
        if self
            .mkskipped
            .contains_key(&(header.public_key.to_bytes(), header.n))
        {
            let mk = *self
                .mkskipped
                .get(&(header.public_key.to_bytes(), header.n))
                .unwrap();
            self.mkskipped
                .remove(&(header.public_key.to_bytes(), header.n))
                .unwrap();
            Some(decrypt(&mk, enc_data, &header.concat(associated_data), nonce))
        } else {
            None
        }
    }

    fn skip_message_keys(&mut self, until: usize) -> Result<(), &str> {
        if self.nr + MAX_SKIP < until {
            return Err("Skipped to many keys");
        }
        match self.ckr {
            Some(mut d) => {
                while self.nr < until {
                    let (ckr, mk) = kdf_ck(&d);
                    self.ckr = Some(ckr);
                    d = ckr;
                    self.mkskipped
                        .insert((self.dhr.unwrap().to_bytes(), self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            }
            None => Err("No Ckr set"),
        }
    }

    /// Decrypt encrypted bytes with a [Ratchet].
    /// Requires a [Header], encrypted bytes, a nonce, and associated bytes.
    /// Returns decrypted bytes.
    pub fn decrypt(
        &mut self,
        header: &Header,
        enc_data: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Vec<u8> {
        let data = self.try_skipped_message_keys(header, enc_data, nonce, associated_data);
        match data {
            Some(d) => d,
            None => {
                if Some(header.public_key) != self.dhr {
                    if self.ckr != None {
                        self.skip_message_keys(header.pn).unwrap();
                    }
                    self.dhratchet(header);
                }
                self.skip_message_keys(header.n).unwrap();
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                self.ckr = Some(ckr);
                self.nr += 1;
                decrypt(&mk, enc_data, &header.concat(associated_data), nonce)
            }
        }
    }

    fn dhratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.public_key);
        let (rk, ckr) = kdf_rk(&self.rk, &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = DhKeyPair::new();
        let (rk, cks) = kdf_rk(&self.rk, &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.cks = Some(cks);
    }

    /// Export a [Ratchet].
    /// Returns bytes.
    pub fn export(&self) -> Vec<u8> {
        postcard::to_allocvec(&self).unwrap()
    }

    /// Import a previously exported [Ratchet].
    /// Requires bytes.
    /// Returns a [Ratchet], or nothing if invalid data is provided.
    pub fn import(data: &[u8]) -> Option<Self> {
        postcard::from_bytes(data).ok()
    }
}

/// A [Ratchet], but with header encryption.
#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct RatchetEncHeader {
    dhs: DhKeyPair,
    dhr: Option<PublicKey>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: usize,
    nr: usize,
    pn: usize,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>,
    mkskipped: HashMap<(Option<[u8; 32]>, usize), [u8; 32]>,
}

impl Zeroize for RatchetEncHeader {
    fn zeroize(&mut self) {
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        self.hks.zeroize();
        self.hkr.zeroize();
        self.nhks.zeroize();
        self.nhkr.zeroize();
        self.mkskipped.clear();
    }
}

impl Drop for RatchetEncHeader {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RatchetEncHeader {
    /// Initialize a [RatchetEncHeader] with a remote [PublicKey]. Initialized second.
    /// Requires a shared key, a [PublicKey], a shared HKA, and a shared NHKB.
    /// Returns a [RatchetEncHeader].
    pub fn init_alice(
        sk: [u8; 32],
        bob_dh_public_key: PublicKey,
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> Self {
        let dhs = DhKeyPair::new();
        let (rk, cks, nhks) = kdf_rk_he(&sk, &dhs.key_agreement(&bob_dh_public_key));
        RatchetEncHeader {
            dhs,
            dhr: Some(bob_dh_public_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            hks: Some(shared_hka),
            hkr: None,
            nhkr: Some(shared_nhkb),
            nhks: Some(nhks),
        }
    }

    /// Initialize a [RatchetEncHeader] without a remote [PublicKey]. Initialized first.
    /// Requires a shared key, a shared HKA, and a shared NHKB.
    /// Returns a [RatchetEncHeader] and a [PublicKey].
    pub fn init_bob(
        sk: [u8; 32],
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> (Self, PublicKey) {
        let dhs = DhKeyPair::new();
        let public_key = dhs.public_key;
        let ratchet = Self {
            dhs,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            hks: None,
            nhks: Some(shared_nhkb),
            hkr: None,
            nhkr: Some(shared_hka),
        };
        (ratchet, public_key)
    }

    /// Encrypt bytes with a [RatchetEncHeader].
    /// Requires bytes and associated bytes.
    /// Returns an [EncryptedHeader], encrypted bytes, and a nonce.
    pub fn encrypt(&mut self, data: &[u8], associated_data: &[u8]) -> (EncryptedHeader, Vec<u8>, [u8; 12]) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        let enc_header = header.encrypt(&self.hks.unwrap(), associated_data);
        self.ns += 1;
        let encrypted = encrypt(&mk, data, &header.concat(associated_data));
        (enc_header, encrypted.0, encrypted.1)
    }

    fn try_skipped_message_keys(
        &mut self,
        enc_header: &EncryptedHeader,
        enc_data: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> (Option<Vec<u8>>, Option<Header>) {
        let ret_data = self.mkskipped.clone().into_iter().find(|e| {
            let header = enc_header.decrypt(&e.0.0);
            match header {
                None => false,
                Some(h) => h.n == e.0 .1,
            }
        });
        match ret_data {
            None => (None, None),
            Some(data) => {
                let header = enc_header.decrypt(&data.0.0);
                let mk = data.1;
                self.mkskipped.remove(&(data.0 .0, data.0 .1));
                (
                    Some(decrypt(
                        &mk,
                        enc_data,
                        &header.clone().unwrap().concat(associated_data),
                        nonce,
                    )),
                    header,
                )
            }
        }
    }

    /// Decrypt an [EncryptedHeader] with a [RatchetEncHeader].
    /// Requires an [EncryptedHeader].
    /// Returns a decrypted [Header] and boolean, if decryption was successful.
    fn decrypt_header(&mut self, enc_header: &EncryptedHeader) -> Result<(Header, bool), &str> {
        let header = enc_header.decrypt(&self.hkr);
        if let Some(h) = header {
            return Ok((h, false));
        };
        let header = enc_header.decrypt(&self.nhkr);
        match header {
            Some(h) => Ok((h, true)),
            None => Err("Header is unencryptable!"),
        }
    }

    fn skip_message_keys(&mut self, until: usize) -> Result<(), &str> {
        if self.nr + MAX_SKIP < until {
            return Err("Skipping went wrong");
        }
        if let Some(d) = &mut self.ckr {
            while self.nr < until {
                let (ckr, mk) = kdf_ck(d);
                *d = ckr;
                self.mkskipped.insert((self.hkr, self.nr), mk);
                self.nr += 1
            }
        }
        Ok(())
    }

    fn dhratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = self.nhks;
        self.hkr = self.nhkr;
        self.dhr = Some(header.public_key);
        let (rk, ckr, nhkr) = kdf_rk_he(&self.rk, &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = Some(nhkr);
        self.dhs = DhKeyPair::new();
        let (rk, cks, nhks) = kdf_rk_he(&self.rk, &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.cks = Some(cks);
        self.nhks = Some(nhks);
    }

    /// Decrypt encrypted bytes with a [RatchetEncHeader].
    /// Requires an [EncryptedHeader], encrypted bytes, a nonce, and associated bytes.
    /// Returns decrypted bytes.
    pub fn decrypt(
        &mut self,
        enc_header: &EncryptedHeader,
        enc_data: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Vec<u8> {
        let (data, _) = self.try_skipped_message_keys(enc_header, enc_data, nonce, associated_data);
        if let Some(d) = data {
            return d;
        };
        let (header, dh_ratchet) = self.decrypt_header(enc_header).unwrap();
        if dh_ratchet {
            self.skip_message_keys(header.pn).unwrap();
            self.dhratchet(&header);
        }
        self.skip_message_keys(header.n).unwrap();
        let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
        self.ckr = Some(ckr);
        self.nr += 1;
        decrypt(&mk, enc_data, &header.concat(associated_data), nonce)
    }

    /// Decrypt encrypted bytes and an [EncryptedHeader] with a [RatchetEncHeader].
    /// Requires an [EncryptedHeader], encrypted bytes, a nonce, and associated bytes.
    /// Returns decrypted bytes and a [Header].
    pub fn decrypt_with_header(
        &mut self,
        enc_header: &EncryptedHeader,
        enc_data: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> (Vec<u8>, Header) {
        let (data, header) = self.try_skipped_message_keys(enc_header, enc_data, nonce, associated_data);
        if let Some(d) = data {
            return (d, header.unwrap());
        };
        let (header, dh_ratchet) = self.decrypt_header(enc_header).unwrap();
        if dh_ratchet {
            self.skip_message_keys(header.pn).unwrap();
            self.dhratchet(&header);
        }
        self.skip_message_keys(header.n).unwrap();
        let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
        self.ckr = Some(ckr);
        self.nr += 1;
        (
            decrypt(&mk, enc_data, &header.concat(associated_data), nonce),
            header,
        )
    }

    /// Export a [RatchetEncHeader].
    /// Returns bytes.
    pub fn export(&self) -> Vec<u8> {
        postcard::to_allocvec(&self).unwrap()
    }

    /// Import a previously exported [RatchetEncHeader].
    /// Requires bytes.
    /// Returns a [RatchetEncHeader], or nothing if invalid data is provided.
    pub fn import(data: &[u8]) -> Option<Self> {
        postcard::from_bytes(data).ok()
    }
}
