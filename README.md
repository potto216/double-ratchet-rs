[![Crate](https://img.shields.io/crates/v/double-ratchet-rs)](https://crates.io/crates/double-ratchet-rs)
[![License](https://img.shields.io/github/license/notsatvrn/double-ratchet-rs)](https://github.com/notsatvrn/double-ratchet-rs/blob/main/LICENSE)
[![Coverage Status](https://coveralls.io/repos/github/notsatvrn/double-ratchet-rs/badge.svg?branch=main)](https://coveralls.io/github/notsatvrn/double-ratchet-rs?branch=main)
[![Workflow Status](https://github.com/notsatvrn/double-ratchet-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/notsatvrn/double-ratchet-rs/actions/workflows/rust.yml)

# double-ratchet-rs 

A pure Rust implementation of the Double Ratchet Algorithm as specified by [Signal][1].

This implementation follows the cryptographic recommendations provided by [Signal][2].
The AEAD Algorithm uses a constant Nonce. This might be changed in the future.

Fork of [double-ratchet-2](https://github.com/Dione-Software/double-ratchet-2).

## Examples

### Standard Usage

Alice encrypts a message which is then decrypted by Bob.

```rust
use double_ratchet_rs::Ratchet;

let sk = [1; 32]; // Shared key created by a symmetric key agreement protocol

let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);   // Creating Bob's Ratchet (returns Bob's PublicKey)
let mut alice_ratchet = Ratchet::init_alice(sk, public_key); // Creating Alice's Ratchet with Bob's PublicKey

let data = b"Hello World".to_vec(); // Data to be encrypted
let ad = b"Associated Data";        // Associated data

let (header, encrypted, nonce) = alice_ratchet.encrypt(&data, ad);    // Encrypting message with Alice's Ratchet (Alice always needs to send the first message)
let decrypted = bob_ratchet.decrypt(&header, &encrypted, &nonce, ad); // Decrypt message with Bob's Ratchet

assert_eq!(data, decrypted)
```

### Recovering a Lost Message

Alice encrypts 2 messages for Bob.
The latest message must be decrypted first.

```rust
use double_ratchet_rs::Ratchet;

let sk = [1; 32]; // Shared key created by a symmetric key agreement protocol

let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);   // Creating Bob's Ratchet (returns Bob's PublicKey)
let mut alice_ratchet = Ratchet::init_alice(sk, public_key); // Creating Alice's Ratchet with Bob's PublicKey

let data = b"Hello World".to_vec(); // Data to be encrypted
let ad = b"Associated Data";        // Associated data

let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, ad); // Lost message
let (header2, encrypted2, nonce2) = alice_ratchet.encrypt(&data, ad); // Successful message

let decrypted2 = bob_ratchet.decrypt(&header2, &encrypted2, &nonce2, ad); // Decrypting second message first
let decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, ad); // Decrypting latter message

assert_eq!(data, decrypted1);
assert_eq!(data, decrypted2);
```

### Encryption Before Decrypting First Message

Bob encrypts a message before decrypting one from Alice.
This will result in a panic.

```rust
use double_ratchet_rs::Ratchet;

let sk = [1; 32];

let (mut bob_ratchet, _) = Ratchet::init_bob(sk);

let data = b"Hello World".to_vec();
let ad = b"Associated Data";

let (_, _, _) = bob_ratchet.encrypt(&data, ad);
```

### Encryption After Decrypting First Message

Bob *can* also encrypt messages.
This is only possible after decrypting one from Alice first though.

```rust
use double_ratchet_rs::Ratchet;

let sk = [1; 32];

let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
let mut alice_ratchet = Ratchet::init_alice(sk, public_key);

let data = b"Hello World".to_vec();
let ad = b"Associated Data";

let (header1, encrypted1, nonce1) = alice_ratchet.encrypt(&data, ad);
let _decrypted1 = bob_ratchet.decrypt(&header1, &encrypted1, &nonce1, ad);

let (header2, encrypted2, nonce2) = bob_ratchet.encrypt(&data, ad);
let decrypted2 = alice_ratchet.decrypt(&header2, &encrypted2, &nonce2, ad);

assert_eq!(data, decrypted2);
```

### Constructing and Deconstructing Headers

```rust
use double_ratchet_rs::{Header, Ratchet};

let sk = [1; 32];

let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
let mut alice_ratchet = Ratchet::init_alice(sk, public_key);

let data = b"hello World".to_vec();
let ad = b"Associated Data";

let (header, _, _) = alice_ratchet.encrypt(&data, ad);
let header_bytes: Vec<u8> = header.clone().into();
let header_const = Header::from(header_bytes);

assert_eq!(header, header_const);
```

### Encrypted Headers

```rust
use double_ratchet_rs::RatchetEncHeader;

let sk = [0; 32];
let shared_hka = [1; 32];
let shared_nhkb = [2; 32];

let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);

let data = b"Hello World".to_vec();
let ad = b"Associated Data";

let (header, encrypted, nonce) = alice_ratchet.encrypt(&data, ad);
let decrypted = bob_ratchet.decrypt(&header, &encrypted, &nonce, ad);

assert_eq!(data, decrypted)
```

### Exporting / Importing Ratchet w/ Encrypted Headers

This can be used for storing and using ratchets in a file.

```rust
use double_ratchet_rs::RatchetEncHeader;

let sk = [0; 32];
let shared_hka = [1; 32];
let shared_nhkb = [2; 32];

let (bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
let ex_ratchet = bob_ratchet.export();
let im_ratchet = RatchetEncHeader::import(&ex_ratchet).unwrap();

assert_eq!(im_ratchet, bob_ratchet)
```

## **M**inimum **S**upported **R**ust **V**ersion (MSRV)

The current MSRV is 1.61.0.

## License

This project is licensed under the [MIT license](https://github.com/notsatvrn/double-ratchet-rs/blob/main/LICENSE).

[1]: https://signal.org/docs/specifications/doubleratchet/
[2]: https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
[3]: https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption

