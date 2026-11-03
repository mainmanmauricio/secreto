//! HPKE (RFC 9180) Base mode with KEM `0x0051` (MLKEM1024-P384),
//! KDF `0x0003` (HKDF-SHA512) and AEAD `0x0003` (ChaCha20Poly1305).
//!
//! The labeled Extract/Expand and key schedule are generic over the suite
//! identifiers so they can be validated against RFC 9180 Appendix A.6
//! (P-521, HKDF-SHA512) values.

use crate::error::{Error, Result};
use crate::kem;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// KEM id of MLKEM1024-P384.
pub const KEM_ID: u16 = 0x0051;
/// KDF id of HKDF-SHA512.
pub const KDF_ID: u16 = 0x0003;
/// AEAD id of ChaCha20Poly1305.
pub const AEAD_ID: u16 = 0x0003;
/// HPKE `info` used for the mlkem1024p384 recipient type.
pub const INFO: &[u8] = b"secreto/v1/mlkem1024p384";

/// Nk: AEAD key length.
pub const NK: usize = 32;
/// Nn: AEAD nonce length.
pub const NN: usize = 12;
/// Nh: KDF hash output length.
pub const NH: usize = 64;
/// Length of the AEAD tag.
pub const TAG_LEN: usize = 16;

const BASE_MODE: u8 = 0x00;
const VERSION_LABEL: &[u8] = b"HPKE-v1";

/// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
pub fn suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&kem_id.to_be_bytes());
    s[6..8].copy_from_slice(&kdf_id.to_be_bytes());
    s[8..10].copy_from_slice(&aead_id.to_be_bytes());
    s
}

/// The suite id for secreto/v1.
pub fn secreto_suite_id() -> [u8; 10] {
    suite_id(KEM_ID, KDF_ID, AEAD_ID)
}

/// `LabeledExtract(salt, label, ikm)` with HKDF-SHA512. Returns the PRK.
pub fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Zeroizing<[u8; NH]> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), &labeled);
    let mut out = Zeroizing::new([0u8; NH]);
    out.copy_from_slice(&prk);
    out
}

/// `LabeledExpand(prk, label, info, L)` with HKDF-SHA512.
pub fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let l = u16::try_from(len).map_err(|_| Error::Format("HPKE expand length"))?;
    let l_bytes = l.to_be_bytes();
    let hk = Hkdf::<Sha512>::from_prk(prk).map_err(|_| Error::Format("HPKE PRK length"))?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    hk.expand_multi_info(&[&l_bytes, VERSION_LABEL, suite_id, label, info], &mut out)
        .map_err(|_| Error::Format("HPKE expand length"))?;
    Ok(out)
}

/// Output of the Base-mode key schedule.
pub struct KeySchedule {
    /// `key_schedule_context` (for testing).
    pub context: Vec<u8>,
    /// `secret` (for testing).
    pub secret: Zeroizing<[u8; NH]>,
    /// AEAD key.
    pub key: Zeroizing<[u8; NK]>,
    /// Base nonce.
    pub base_nonce: [u8; NN],
    /// Exporter secret.
    pub exporter_secret: Zeroizing<[u8; NH]>,
}

/// RFC 9180 §5.1 `KeySchedule(mode_base, shared_secret, info, psk="", psk_id="")`.
pub fn key_schedule_base(
    suite_id: &[u8],
    shared_secret: &[u8],
    info: &[u8],
) -> Result<KeySchedule> {
    let psk_id_hash = labeled_extract(suite_id, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(suite_id, b"", b"info_hash", info);
    let mut context = Vec::with_capacity(1 + 2 * NH);
    context.push(BASE_MODE);
    context.extend_from_slice(&*psk_id_hash);
    context.extend_from_slice(&*info_hash);

    let secret = labeled_extract(suite_id, shared_secret, b"secret", b"");
    let key_v = labeled_expand(suite_id, &*secret, b"key", &context, NK)?;
    let nonce_v = labeled_expand(suite_id, &*secret, b"base_nonce", &context, NN)?;
    let exp_v = labeled_expand(suite_id, &*secret, b"exp", &context, NH)?;

    let mut key = Zeroizing::new([0u8; NK]);
    key.copy_from_slice(&key_v);
    let mut base_nonce = [0u8; NN];
    base_nonce.copy_from_slice(&nonce_v);
    let mut exporter_secret = Zeroizing::new([0u8; NH]);
    exporter_secret.copy_from_slice(&exp_v);
    Ok(KeySchedule {
        context,
        secret,
        key,
        base_nonce,
        exporter_secret,
    })
}

/// `nonce = base_nonce XOR I2OSP(seq, Nn)`.
pub fn compute_nonce(base_nonce: &[u8; NN], seq: u64) -> [u8; NN] {
    let mut n = *base_nonce;
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[NN - 8 + i] ^= s[i];
    }
    n
}

fn aead_seal(ks: &KeySchedule, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new((&*ks.key).into());
    let nonce = compute_nonce(&ks.base_nonce, 0);
    cipher
        .encrypt((&nonce).into(), Payload { msg: pt, aad })
        .map_err(|_| Error::Format("HPKE seal failure"))
}

fn aead_open(ks: &KeySchedule, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = ChaCha20Poly1305::new((&*ks.key).into());
    let nonce = compute_nonce(&ks.base_nonce, 0);
    cipher
        .decrypt((&nonce).into(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::NoMatch)
}

/// HPKE `SealBase` to the encapsulation key `ek` (1665 bytes) with sequence
/// number 0. Returns `(enc, ciphertext)`.
pub fn seal_base(ek: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (ss, enc) = kem::encapsulate(ek)?;
    seal_with_shared_secret(&*ss, enc, info, aad, pt)
}

/// `SealBase` using a caller-provided KEM output (also used by tests).
pub fn seal_with_shared_secret(
    shared_secret: &[u8],
    enc: Vec<u8>,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let ks = key_schedule_base(&secreto_suite_id(), shared_secret, info)?;
    let ct = aead_seal(&ks, aad, pt)?;
    Ok((enc, ct))
}

/// HPKE `OpenBase` with the 32-byte KEM seed `dk`.
///
/// Returns [`Error::NoMatch`] if the KEM output is invalid or the AEAD does
/// not verify.
pub fn open_base(
    enc: &[u8],
    dk_seed: &[u8; kem::SEED_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let ss = kem::decapsulate(dk_seed, enc).map_err(|_| Error::NoMatch)?;
    let ks = key_schedule_base(&secreto_suite_id(), &*ss, info)?;
    aead_open(&ks, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Suite {
        mode: u8,
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
    }
    #[derive(Deserialize)]
    struct File {
        suite: Suite,
        info: String,
        shared_secret: String,
        key_schedule_context: String,
        secret: String,
        key: String,
        base_nonce: String,
        exporter_secret: String,
        encryptions: Vec<Enc>,
    }
    #[derive(Deserialize)]
    struct Enc {
        sequence_number: u64,
        nonce: String,
    }

    fn load() -> File {
        let p = crate::test_util::vector_path("hpke_key_schedule_sha512.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn key_schedule_vector_a6() {
        let f = load();
        assert_eq!(f.suite.mode, 0);
        let sid = suite_id(f.suite.kem_id, f.suite.kdf_id, f.suite.aead_id);
        assert_eq!(&sid[..4], b"HPKE");
        let ks = key_schedule_base(
            &sid,
            &hex::decode(&f.shared_secret).unwrap(),
            &hex::decode(&f.info).unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(&ks.context), f.key_schedule_context);
        assert_eq!(hex::encode(*ks.secret), f.secret);
        assert_eq!(hex::encode(*ks.key), f.key);
        assert_eq!(hex::encode(ks.base_nonce), f.base_nonce);
        assert_eq!(hex::encode(*ks.exporter_secret), f.exporter_secret);
        for e in &f.encryptions {
            assert_eq!(
                hex::encode(compute_nonce(&ks.base_nonce, e.sequence_number)),
                e.nonce
            );
        }
    }

    #[test]
    fn suite_id_secreto() {
        assert_eq!(
            secreto_suite_id(),
            [b'H', b'P', b'K', b'E', 0x00, 0x51, 0x00, 0x03, 0x00, 0x03]
        );
    }

    #[test]
    fn labeled_expand_length_limits() {
        let prk = [1u8; NH];
        assert!(labeled_expand(b"s", &prk, b"l", b"", 70000).is_err());
        assert_eq!(labeled_expand(b"s", &prk, b"l", b"", 32).unwrap().len(), 32);
        assert!(labeled_expand(b"s", &prk[..10], b"l", b"", 32).is_err());
    }

    #[test]
    fn seal_open_roundtrip() {
        let seed = [9u8; 32];
        let (_, ek) = kem::derive_key_pair(&seed).unwrap();
        let pt = [0xabu8; 32];
        let (enc, ct) = seal_base(&ek, INFO, b"", &pt).unwrap();
        assert_eq!(enc.len(), kem::CT_LEN);
        assert_eq!(ct.len(), 32 + TAG_LEN);
        let got = open_base(&enc, &seed, INFO, b"", &ct).unwrap();
        assert_eq!(&got[..], &pt[..]);

        // wrong info / aad / key / tampering all fail with NoMatch
        assert_eq!(
            open_base(&enc, &seed, b"other", b"", &ct).unwrap_err(),
            Error::NoMatch
        );
        assert_eq!(
            open_base(&enc, &seed, INFO, b"x", &ct).unwrap_err(),
            Error::NoMatch
        );
        assert_eq!(
            open_base(&enc, &[1u8; 32], INFO, b"", &ct).unwrap_err(),
            Error::NoMatch
        );
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            open_base(&enc, &seed, INFO, b"", &bad).unwrap_err(),
            Error::NoMatch
        );
        let mut bad_enc = enc.clone();
        bad_enc[0] ^= 1;
        assert!(open_base(&bad_enc, &seed, INFO, b"", &ct).is_err());
    }
}
