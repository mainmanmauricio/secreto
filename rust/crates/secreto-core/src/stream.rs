// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! STREAM ChaCha20-Poly1305 payload (`spec/format.md`, *Payload*).
//!
//! Payload layout: `nonce (16) || chunk_0 || ... || chunk_n`, where each
//! chunk is the AEAD encryption of up to 64 KiB of plaintext and carries a
//! 16-byte tag. The 12-byte chunk nonce is `be_u88(counter) || flag` with
//! `flag = 1` for the final chunk.

use crate::error::{Error, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 65536;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Length of the random payload nonce.
pub const NONCE_LEN: usize = 16;
/// HKDF info for the payload key.
pub const PAYLOAD_INFO: &[u8] = b"secreto/v1/payload";
/// Largest chunk counter (88 bits).
pub const MAX_COUNTER: u128 = (1u128 << 88) - 1;

/// Build the 12-byte STREAM nonce.
pub fn chunk_nonce(counter: u128, last: bool) -> Result<[u8; 12]> {
    if counter > MAX_COUNTER {
        return Err(Error::Format("STREAM counter overflow"));
    }
    let mut n = [0u8; 12];
    n[..11].copy_from_slice(&counter.to_be_bytes()[5..]);
    n[11] = u8::from(last);
    Ok(n)
}

/// Derive the payload key from the file key and the 16-byte payload nonce.
pub fn payload_key(file_key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(nonce), file_key);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(PAYLOAD_INFO, &mut *out).expect("32 <= 255 * 64");
    out
}

/// Incremental STREAM encryptor.
pub struct StreamEncryptor {
    cipher: ChaCha20Poly1305,
    counter: u128,
    finished: bool,
}

impl StreamEncryptor {
    /// New encryptor for the given payload key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            counter: 0,
            finished: false,
        }
    }

    /// Encrypt the next chunk. `chunk.len()` must be `<= CHUNK_SIZE`; every
    /// non-final chunk must be exactly `CHUNK_SIZE` bytes.
    pub fn encrypt_chunk(&mut self, chunk: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished || chunk.len() > CHUNK_SIZE || (!last && chunk.len() != CHUNK_SIZE) {
            return Err(Error::Format("invalid STREAM chunk"));
        }
        let nonce = chunk_nonce(self.counter, last)?;
        let ct = self
            .cipher
            .encrypt((&nonce).into(), chunk)
            .map_err(|_| Error::Format("AEAD failure"))?;
        self.counter += 1;
        self.finished = last;
        Ok(ct)
    }
}

/// Incremental STREAM decryptor.
pub struct StreamDecryptor {
    cipher: ChaCha20Poly1305,
    counter: u128,
    finished: bool,
}

impl StreamDecryptor {
    /// New decryptor for the given payload key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            counter: 0,
            finished: false,
        }
    }

    /// Decrypt the next chunk. `chunk` includes the tag. Non-final chunks
    /// must be exactly `CHUNK_SIZE + TAG_LEN` bytes. An empty final chunk is
    /// always rejected (secreto/v1 plaintext is never empty).
    pub fn decrypt_chunk(&mut self, chunk: &[u8], last: bool) -> Result<Zeroizing<Vec<u8>>> {
        const E: Error = Error::Format("payload authentication failed");
        if self.finished || chunk.len() < TAG_LEN + usize::from(last) {
            return Err(E);
        }
        if chunk.len() > CHUNK_SIZE + TAG_LEN || (!last && chunk.len() != CHUNK_SIZE + TAG_LEN) {
            return Err(E);
        }
        let nonce = chunk_nonce(self.counter, last)?;
        let pt = self.cipher.decrypt((&nonce).into(), chunk).map_err(|_| E)?;
        self.counter += 1;
        self.finished = last;
        Ok(Zeroizing::new(pt))
    }
}

/// Encrypt `plaintext` into `nonce || ciphertext`.
///
/// `plaintext` must not be empty (secreto/v1 inner plaintext is always at
/// least two bytes).
pub fn encrypt(file_key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(Error::Format("empty STREAM plaintext"));
    }
    let key = payload_key(file_key, nonce);
    let mut enc = StreamEncryptor::new(&key);
    let n_chunks = plaintext.len().div_ceil(CHUNK_SIZE);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + n_chunks * TAG_LEN);
    out.extend_from_slice(nonce);
    for (i, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        out.extend_from_slice(&enc.encrypt_chunk(chunk, i + 1 == n_chunks)?);
    }
    Ok(out)
}

/// Decrypt `nonce || ciphertext`. No plaintext is returned unless every
/// chunk (including a proper final chunk) verifies.
pub fn decrypt(file_key: &[u8; 32], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    const E: Error = Error::Format("payload authentication failed");
    if payload.len() < NONCE_LEN + TAG_LEN + 1 {
        return Err(E);
    }
    let (nonce, body) = payload.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split");
    let key = payload_key(file_key, &nonce);
    let mut dec = StreamDecryptor::new(&key);

    let full = CHUNK_SIZE + TAG_LEN;
    let mut out = Zeroizing::new(Vec::with_capacity(body.len()));
    let n_chunks = body.len().div_ceil(full);
    for (i, chunk) in body.chunks(full).enumerate() {
        let pt = dec.decrypt_chunk(chunk, i + 1 == n_chunks)?;
        out.extend_from_slice(&pt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct NonceEx {
        counter: u128,
        #[serde(rename = "final")]
        fin: bool,
        nonce_hex: String,
    }
    #[derive(Deserialize)]
    struct File {
        chunk_size: usize,
        nonce_examples: Vec<NonceEx>,
    }

    #[test]
    fn nonce_vectors() {
        let p = crate::test_util::vector_path("stream.json");
        let f: File = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert_eq!(f.chunk_size, CHUNK_SIZE);
        for e in f.nonce_examples {
            let n = chunk_nonce(e.counter, e.fin).unwrap();
            assert_eq!(hex::encode(n), e.nonce_hex, "counter={}", e.counter);
        }
        assert!(chunk_nonce(MAX_COUNTER + 1, false).is_err());
        let n = chunk_nonce(MAX_COUNTER, true).unwrap();
        assert_eq!(&n[..11], &[0xffu8; 11]);
        assert_eq!(n[11], 1);
    }

    const FK: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 16] = [0x24; 16];

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_boundaries() {
        for n in [
            1,
            2,
            100,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 5,
        ] {
            let pt = data(n);
            let ct = encrypt(&FK, &NONCE, &pt).unwrap();
            let chunks = n.div_ceil(CHUNK_SIZE);
            assert_eq!(ct.len(), NONCE_LEN + n + chunks * TAG_LEN, "n={n}");
            assert_eq!(&ct[..16], &NONCE);
            assert_eq!(&decrypt(&FK, &ct).unwrap()[..], &pt[..], "n={n}");
        }
    }

    #[test]
    fn rejects_empty_plaintext_and_tiny_payloads() {
        assert!(encrypt(&FK, &NONCE, &[]).is_err());
        assert!(decrypt(&FK, &[]).is_err());
        assert!(decrypt(&FK, &NONCE).is_err());
        // nonce + bare tag-sized final chunk (empty plaintext) must be rejected
        let key = payload_key(&FK, &NONCE);
        let mut enc = StreamEncryptor::new(&key);
        let empty_final = enc.encrypt_chunk(&[], true).unwrap();
        let mut p = NONCE.to_vec();
        p.extend_from_slice(&empty_final);
        assert!(decrypt(&FK, &p).is_err());
    }

    #[test]
    fn empty_final_chunk_after_full_chunk_rejected() {
        let key = payload_key(&FK, &NONCE);
        let mut enc = StreamEncryptor::new(&key);
        let pt = data(CHUNK_SIZE);
        let mut p = NONCE.to_vec();
        p.extend_from_slice(&enc.encrypt_chunk(&pt, false).unwrap());
        p.extend_from_slice(&enc.encrypt_chunk(&[], true).unwrap());
        assert!(decrypt(&FK, &p).is_err());
    }

    #[test]
    fn detects_tampering_truncation_reorder_extension() {
        let pt = data(3 * CHUNK_SIZE + 10);
        let ct = encrypt(&FK, &NONCE, &pt).unwrap();
        // bit flips
        for pos in [0usize, 15, 16, 100, ct.len() / 2, ct.len() - 1] {
            let mut t = ct.clone();
            t[pos] ^= 0x01;
            assert!(decrypt(&FK, &t).is_err(), "flip at {pos}");
        }
        // truncation at chunk boundaries and elsewhere
        let full = CHUNK_SIZE + TAG_LEN;
        for cut in [
            ct.len() - 1,
            NONCE_LEN + full,
            NONCE_LEN + 2 * full,
            NONCE_LEN + 3 * full,
            NONCE_LEN + 1,
        ] {
            assert!(decrypt(&FK, &ct[..cut]).is_err(), "cut {cut}");
        }
        // extension
        let mut t = ct.clone();
        t.push(0);
        assert!(decrypt(&FK, &t).is_err());
        let mut t = ct.clone();
        t.extend_from_slice(&ct[NONCE_LEN..NONCE_LEN + full]);
        assert!(decrypt(&FK, &t).is_err());
        // reorder chunks 0 and 1
        let mut t = ct.clone();
        let (a, b) = (NONCE_LEN, NONCE_LEN + full);
        let c0 = ct[a..a + full].to_vec();
        let c1 = ct[b..b + full].to_vec();
        t[a..a + full].copy_from_slice(&c1);
        t[b..b + full].copy_from_slice(&c0);
        assert!(decrypt(&FK, &t).is_err());
        // wrong key
        assert!(decrypt(&[0u8; 32], &ct).is_err());
    }

    #[test]
    fn encryptor_rules() {
        let key = payload_key(&FK, &NONCE);
        let mut e = StreamEncryptor::new(&key);
        assert!(e.encrypt_chunk(&[1, 2, 3], false).is_err()); // short non-final
        assert!(e.encrypt_chunk(&vec![0; CHUNK_SIZE + 1], true).is_err());
        e.encrypt_chunk(&[1], true).unwrap();
        assert!(e.encrypt_chunk(&[1], true).is_err()); // after final
    }

    #[test]
    fn payload_key_depends_on_nonce() {
        assert_ne!(*payload_key(&FK, &[0; 16]), *payload_key(&FK, &[1; 16]));
    }
}
