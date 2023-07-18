use double_ratchet_rs::{Ratchet, RatchetEncHeader};
extern crate alloc;

#[test]
fn init() {
    let sk = [1; 32];
    let (_bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let _alice_ratchet = Ratchet::init_alice(sk, public_key);
}

#[test]
fn enc_single() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.encrypt(&data, b"");
    let decrypted = bob_ratchet.decrypt(&header, &encrypted, &nonce, b"");
    assert_eq!(data, decrypted)
}

#[test]
fn enc_skip() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, b"");
    let (header2, encrypted2, nonce2) = alice_ratchet.encrypt(&data, b"");
    let (header3, encrypted3, nonce3) = alice_ratchet.encrypt(&data, b"");
    let decrypted3 = bob_ratchet.decrypt(&header3, &encrypted3, &nonce3, b"");
    let decrypted2 = bob_ratchet.decrypt(&header2, &encrypted2, &nonce2, b"");
    let decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, b"");
    let comp_res = decrypted1 == data && decrypted2 == data && decrypted3 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn panic_bob() {
    let sk = [1; 32];
    let (mut bob_ratchet, _) = Ratchet::init_bob(sk);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (_, _, _) = bob_ratchet.encrypt(&data, b"");
}

#[test]
fn encryt_decrypt_four() {
    let sk = [1; 32];
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, b"");
    let decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, b"");
    let (header2, encrypted2, nonce2) = bob_ratchet.encrypt(&data, b"");
    let decrypted2 = alice_ratchet.decrypt(&header2, &encrypted2, &nonce2, b"");
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
fn ench_init() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (_bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let _alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
}

#[test]
fn ench_enc_single() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.encrypt(&data, b"");
    let decrypted = bob_ratchet.decrypt(&header, &encrypted, &nonce, b"");
    assert_eq!(data, decrypted)
}

#[test]
fn ench_enc_skip() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, b"");
    let (header2, encrypted2, nonce2) = alice_ratchet.encrypt(&data, b"");
    let (header3, encrypted3, nonce3) = alice_ratchet.encrypt(&data, b"");
    let decrypted3 = bob_ratchet.decrypt(&header3, &encrypted3, &nonce3, b"");
    let decrypted2 = bob_ratchet.decrypt(&header2, &encrypted2, &nonce2, b"");
    let decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, b"");
    let comp_res = decrypted1 == data && decrypted2 == data && decrypted3 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn ench_panic_bob() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, _) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (_, _, _) = bob_ratchet.encrypt(&data, b"");
}

#[test]
fn ench_decrypt_four() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, b"");
    let decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, b"");
    let (header2, encrypted2, nonce2) = bob_ratchet.encrypt(&data, b"");
    let decrypted2 = alice_ratchet.decrypt(&header2, &encrypted2, &nonce2, b"");
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn ench_enc_skip_panic() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let mut headers = alloc::vec![];
    let mut encrypteds = alloc::vec![];
    let mut nonces = alloc::vec![];
    let mut decrypteds = alloc::vec![];
    for _ in 0..200 {
        let (header, encrypted, nonce) = alice_ratchet.encrypt(&data, b"");
        headers.push(header);
        encrypteds.push(encrypted);
        nonces.push(nonce);
    }
    headers.reverse();
    encrypteds.reverse();
    nonces.reverse();
    for idx in 0..200 {
        let header = headers.get(idx).unwrap();
        let encrypted = encrypteds.get(idx).unwrap();
        let nonce = nonces.get(idx).unwrap();
        let decrypted = bob_ratchet.decrypt(header, encrypted, nonce, b"");
        decrypteds.push(decrypted);
    }
}

#[test]
fn import_export() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);

    let ex_bob_ratchet = bob_ratchet.export();
    let in_bob_ratchet = RatchetEncHeader::import(&ex_bob_ratchet).unwrap();
    assert_eq!(in_bob_ratchet, bob_ratchet);

    let ex_alice_ratchet = alice_ratchet.export();
    let in_alice_ratchet = RatchetEncHeader::import(&ex_alice_ratchet).unwrap();
    assert_eq!(in_alice_ratchet, alice_ratchet);
}
