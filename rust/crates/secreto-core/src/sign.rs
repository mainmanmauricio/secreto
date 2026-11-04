// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Hybrid Ed25519 + ML-DSA-87 signatures (`spec/format.md`, *Signature block*).

use crate::error::{Error, Result};
use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::{
    signature::Keypair as _, KeyExport as _, KeyInit as _, MlDsa87, Signature as MlSignature,
    SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Ed25519 public key length.
pub const ED_PK_LEN: usize = 32;
/// ML-DSA-87 public key length.
pub const MLDSA_PK_LEN: usize = 2592;
/// Combined public key length (`secretosig` data).
pub const PK_LEN: usize = ED_PK_LEN + MLDSA_PK_LEN;
/// Signing secret length: `ed25519 seed (32) || ml-dsa-87 seed (32)`.
pub const SK_LEN: usize = 64;
/// Ed25519 signature length.
pub const ED_SIG_LEN: usize = 64;
/// ML-DSA-87 signature length.
pub const MLDSA_SIG_LEN: usize = 4627;
/// Signer id length.
pub const SIGNER_ID_LEN: usize = 32;
/// Signature block length.
pub const SIGBLOCK_LEN: usize = SIGNER_ID_LEN + ED_SIG_LEN + MLDSA_SIG_LEN;

const SIGNER_ID_LABEL: &[u8] = b"secreto/v1/signer-id";
const MSG_LABEL: &[u8] = b"secreto/v1/signature";

/// `signer_id = SHA-512("secreto/v1/signer-id" || pk_bytes)[:32]`.
pub fn signer_id(pk_bytes: &[u8; PK_LEN]) -> [u8; SIGNER_ID_LEN] {
    let mut h = Sha512::new();
    h.update(SIGNER_ID_LABEL);
    h.update(pk_bytes);
    let d = h.finalize();
    let mut out = [0u8; SIGNER_ID_LEN];
    out.copy_from_slice(&d[..SIGNER_ID_LEN]);
    out
}

/// The signed message from a precomputed content digest (streaming encrypt).
pub fn signature_message_hashed(
    header_mac: &[u8; 64],
    content_len: u64,
    content_hash: &[u8; 64],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(MSG_LABEL.len() + 64 + 8 + 64);
    m.extend_from_slice(MSG_LABEL);
    m.extend_from_slice(header_mac);
    m.extend_from_slice(&content_len.to_be_bytes());
    m.extend_from_slice(content_hash);
    m
}

/// The signed message:
/// `"secreto/v1/signature" || header_mac (64) || content_len (u64 BE) || SHA-512(content)`.
pub fn signature_message(header_mac: &[u8; 64], content: &[u8]) -> Vec<u8> {
    let hash: [u8; 64] = Sha512::digest(content).into();
    signature_message_hashed(header_mac, content.len() as u64, &hash)
}

/// Signer public key (`ed25519_pk || mldsa87_pk`, 2624 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SignerPublicKey(Box<[u8; PK_LEN]>);

impl core::fmt::Debug for SignerPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignerPublicKey({})", hex_prefix(&self.signer_id()))
    }
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl SignerPublicKey {
    /// Construct from the 2624-byte encoding, validating both components.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("invalid signer public key length"))?;
        EdVerifyingKey::from_bytes(arr[..ED_PK_LEN].try_into().expect("32"))
            .map_err(|_| Error::InvalidKey("invalid Ed25519 public key"))?;
        let ml = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(&arr[ED_PK_LEN..])
            .map_err(|_| Error::InvalidKey("invalid ML-DSA public key"))?;
        let _ = MlVerifyingKey::<MlDsa87>::new(&ml);
        Ok(Self(Box::new(arr)))
    }

    /// The 2624-byte encoding.
    pub fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.0
    }

    /// Signer id.
    pub fn signer_id(&self) -> [u8; SIGNER_ID_LEN] {
        signer_id(&self.0)
    }

    /// Verify a signature block over `msg` (both signatures must verify).
    pub fn verify(&self, sig: &SigBlock, msg: &[u8]) -> Result<()> {
        const E: Error = Error::Signature("signature verification failed");
        if sig.signer_id != self.signer_id() {
            return Err(Error::Signature("signature from a different signer"));
        }
        let ed_pk = EdVerifyingKey::from_bytes(self.0[..ED_PK_LEN].try_into().expect("32"))
            .map_err(|_| E)?;
        let ed_sig = EdSignature::from_bytes(&sig.ed25519);
        let ed_ok = ed_pk.verify_strict(msg, &ed_sig).is_ok();

        let ml_enc = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(&self.0[ED_PK_LEN..])
            .map_err(|_| E)?;
        let ml_pk = MlVerifyingKey::<MlDsa87>::new(&ml_enc);
        let ml_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(&sig.mldsa[..])
            .ok()
            .and_then(|e| MlSignature::<MlDsa87>::decode(&e));
        let ml_ok = match ml_sig {
            Some(s) => ml_pk.verify_with_context(msg, b"", &s),
            None => false,
        };
        if ed_ok && ml_ok {
            Ok(())
        } else {
            Err(E)
        }
    }
}

/// Signing secret key (`ed25519 seed || ml-dsa-87 seed`).
pub struct SigningKey {
    bytes: Zeroizing<[u8; SK_LEN]>,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl SigningKey {
    /// Generate a fresh random key.
    pub fn generate() -> Result<Self> {
        let mut b = Zeroizing::new([0u8; SK_LEN]);
        getrandom::fill(&mut *b)
            .map_err(|_| Error::Io("random number generator failure".into()))?;
        Ok(Self { bytes: b })
    }

    /// Construct from the 64-byte secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| Error::InvalidKey("invalid signing key length"))?;
        Ok(Self {
            bytes: Zeroizing::new(arr),
        })
    }

    /// The 64-byte secret.
    pub fn as_bytes(&self) -> &[u8; SK_LEN] {
        &self.bytes
    }

    fn ed(&self) -> EdSigningKey {
        EdSigningKey::from_bytes(self.bytes[..32].try_into().expect("32"))
    }

    fn ml(&self) -> MlSigningKey<MlDsa87> {
        let seed = ml_dsa::Seed::try_from(&self.bytes[32..]).expect("32");
        MlSigningKey::<MlDsa87>::new(&seed)
    }

    /// Public key.
    pub fn public_key(&self) -> SignerPublicKey {
        let mut pk = Box::new([0u8; PK_LEN]);
        pk[..ED_PK_LEN].copy_from_slice(self.ed().verifying_key().as_bytes());
        let ml_pk = self.ml().verifying_key().to_bytes();
        pk[ED_PK_LEN..].copy_from_slice(ml_pk.as_slice());
        SignerPublicKey(pk)
    }

    /// Deterministic variant of [`SigningKey::sign`] (ML-DSA signed with the
    /// all-zero `rnd`), exposed for reproducible test vectors only.
    #[cfg(any(test, feature = "hazmat"))]
    pub fn sign_deterministic(&self, msg: &[u8]) -> Result<SigBlock> {
        let ed_sig = self.ed().sign(msg).to_bytes();
        let ml_sig = self
            .ml()
            .expanded_key()
            .sign_deterministic(msg, b"")
            .map_err(|_| Error::Signature("ML-DSA signing failed"))?;
        let mut mldsa = Box::new([0u8; MLDSA_SIG_LEN]);
        mldsa.copy_from_slice(ml_sig.encode().as_slice());
        Ok(SigBlock {
            signer_id: self.public_key().signer_id(),
            ed25519: ed_sig,
            mldsa,
        })
    }

    /// Sign `msg` with both algorithms, returning the 4723-byte block.
    pub fn sign(&self, msg: &[u8]) -> Result<SigBlock> {
        let ed_sig = self.ed().sign(msg).to_bytes();
        // ML-DSA-87, empty context, hedged signing with OS randomness.
        let ml = self.ml();
        let mut rng = getrandom::SysRng;
        let ml_sig = ml
            .expanded_key()
            .sign_randomized(msg, b"", &mut rng)
            .map_err(|_| Error::Signature("ML-DSA signing failed"))?;
        let ml_bytes = ml_sig.encode();
        let mut mldsa = Box::new([0u8; MLDSA_SIG_LEN]);
        mldsa.copy_from_slice(ml_bytes.as_slice());
        Ok(SigBlock {
            signer_id: self.public_key().signer_id(),
            ed25519: ed_sig,
            mldsa,
        })
    }
}

/// The 4723-byte signature block.
#[derive(Clone, PartialEq, Eq)]
pub struct SigBlock {
    /// Signer id.
    pub signer_id: [u8; SIGNER_ID_LEN],
    /// Ed25519 signature.
    pub ed25519: [u8; ED_SIG_LEN],
    /// ML-DSA-87 signature.
    pub mldsa: Box<[u8; MLDSA_SIG_LEN]>,
}

impl core::fmt::Debug for SigBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigBlock(signer_id={})", hex_prefix(&self.signer_id))
    }
}

impl SigBlock {
    /// Serialize to `signer_id || ed25519_sig || mldsa87_sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIGBLOCK_LEN);
        v.extend_from_slice(&self.signer_id);
        v.extend_from_slice(&self.ed25519);
        v.extend_from_slice(&self.mldsa[..]);
        v
    }

    /// Parse a 4723-byte block.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SIGBLOCK_LEN {
            return Err(Error::Format("truncated signature block"));
        }
        let mut signer_id = [0u8; SIGNER_ID_LEN];
        signer_id.copy_from_slice(&b[..SIGNER_ID_LEN]);
        let mut ed25519 = [0u8; ED_SIG_LEN];
        ed25519.copy_from_slice(&b[SIGNER_ID_LEN..SIGNER_ID_LEN + ED_SIG_LEN]);
        let mut mldsa = Box::new([0u8; MLDSA_SIG_LEN]);
        mldsa.copy_from_slice(&b[SIGNER_ID_LEN + ED_SIG_LEN..]);
        Ok(Self {
            signer_id,
            ed25519,
            mldsa,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 64]).unwrap()
    }

    #[test]
    fn sizes() {
        let sk = key();
        let pk = sk.public_key();
        assert_eq!(pk.as_bytes().len(), 2624);
        let sig = sk.sign(b"hello").unwrap();
        assert_eq!(sig.to_bytes().len(), 4723);
        assert_eq!(SIGBLOCK_LEN, 4723);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = key();
        let pk = sk.public_key();
        let msg = signature_message(&[3u8; 64], b"content");
        let sig = sk.sign(&msg).unwrap();
        pk.verify(&sig, &msg).unwrap();

        // via bytes
        let sig2 = SigBlock::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig, sig2);
        let pk2 = SignerPublicKey::from_bytes(pk.as_bytes()).unwrap();
        pk2.verify(&sig2, &msg).unwrap();
    }

    #[test]
    fn deterministic_public_key() {
        assert_eq!(key().public_key(), key().public_key());
        let other = SigningKey::from_bytes(&[8u8; 64]).unwrap();
        assert_ne!(key().public_key(), other.public_key());
    }

    #[test]
    fn rejects_bad_signatures() {
        let sk = key();
        let pk = sk.public_key();
        let msg = signature_message(&[3u8; 64], b"content");
        let sig = sk.sign(&msg).unwrap();

        // wrong message
        let other = signature_message(&[3u8; 64], b"contenT");
        assert!(pk.verify(&sig, &other).is_err());
        // flipped ed25519 byte
        let mut bad = sig.clone();
        bad.ed25519[0] ^= 1;
        assert!(pk.verify(&bad, &msg).is_err());
        // flipped ml-dsa byte
        let mut bad = sig.clone();
        bad.mldsa[100] ^= 1;
        assert!(pk.verify(&bad, &msg).is_err());
        // wrong signer id
        let mut bad = sig.clone();
        bad.signer_id[0] ^= 1;
        assert!(pk.verify(&bad, &msg).is_err());
        // different key
        let other_pk = SigningKey::from_bytes(&[8u8; 64]).unwrap().public_key();
        assert!(other_pk.verify(&sig, &msg).is_err());
        // truncated block
        assert!(SigBlock::from_bytes(&sig.to_bytes()[..4722]).is_err());
        // bad pk length
        assert!(SignerPublicKey::from_bytes(&pk.as_bytes()[..2623]).is_err());
        assert!(SigningKey::from_bytes(&[0u8; 63]).is_err());
    }

    #[test]
    fn signer_id_definition() {
        let pk = key().public_key();
        let mut h = Sha512::new();
        h.update(b"secreto/v1/signer-id");
        h.update(pk.as_bytes());
        assert_eq!(&h.finalize()[..32], &pk.signer_id());
    }

    #[test]
    fn message_layout() {
        let m = signature_message(&[1u8; 64], b"abc");
        assert_eq!(m.len(), 20 + 64 + 8 + 64);
        assert_eq!(&m[..20], b"secreto/v1/signature");
        assert_eq!(&m[84..92], &3u64.to_be_bytes());
        assert_eq!(&m[92..], &Sha512::digest(b"abc")[..]);
    }
}
