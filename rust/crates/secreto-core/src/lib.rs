// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Reference implementation of the `secreto/v1` file format.
//!
//! * Recipients: MLKEM1024-P384 hybrid KEM + HPKE SealBase (`mlkem1024p384`
//!   stanza) or an Argon2id passphrase (`argon2id` stanza).
//! * Payload: STREAM ChaCha20-Poly1305 with 64 KiB chunks.
//! * Header authenticated with HMAC-SHA-512.
//! * Optional hybrid Ed25519 + ML-DSA-87 signatures and Padmé padding.
//!
//! See `spec/format.md` and `spec/registry.md` in the repository root.
//!
//! ```no_run
//! use secreto_core::{decrypt, encrypt, DecryptOptions, EncryptOptions, Identity, Recipients};
//!
//! let id = Identity::generate().unwrap();
//! let rcpt = id.recipient().unwrap();
//! let ct = encrypt(b"hello", Recipients::Keys(&[rcpt]), &EncryptOptions::default()).unwrap();
//! let pt = decrypt(&ct, &DecryptOptions { identities: &[id], ..Default::default() }).unwrap();
//! assert_eq!(&pt.content[..], b"hello");
//! ```

#![forbid(unsafe_code)]

pub mod argon;
pub mod armor;
pub mod bech32;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod header;
pub mod hpke;
pub mod inner;
pub mod kem;
pub mod keys;
pub mod padme;
pub mod sign;
pub mod stream;

pub use decrypt::{decrypt, decrypt_to, DecryptMeta, DecryptOptions, Decrypted};
pub use encrypt::{
    encrypt, encrypt_armored, encrypt_armored_to, encrypt_to, EncryptOptions, Recipients,
};
pub use error::{Error, Result};
pub use keys::{Identity, Recipient};
pub use sign::{SigBlock, SignerPublicKey, SigningKey};

#[cfg(test)]
pub(crate) mod test_util {
    use std::path::PathBuf;

    /// Path of a component vector file.
    pub fn vector_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../vectors/components")
            .join(name)
    }
}
