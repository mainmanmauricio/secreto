//! MLKEM1024-P384 hybrid KEM (HPKE KEM id `0x0051`), CG framework with the
//! C2PRI combiner, per `draft-irtf-cfrg-concrete-hybrid-kems-04` /
//! `draft-irtf-cfrg-hybrid-kems-12`.
//!
//! * decapsulation key: 32-byte seed
//! * `SHAKE256(seed, 112) = seed_PQ (64) || seed_T (48)`
//! * `ek = ek_PQ (1568) || ek_T (97, uncompressed SEC1)`
//! * `ct = ct_PQ (1568) || ct_T (97)`
//! * `ss = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || "MLKEM1024-P384")`

use crate::error::{Error, Result};
use ml_kem::{
    ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey},
    Decapsulate, KeyExport, Seed as MlKemSeed,
};
use p384::{ecdh, FieldBytes, NonZeroScalar, PublicKey, Sec1Point};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

/// Seed (decapsulation key) length.
pub const SEED_LEN: usize = 32;
/// ML-KEM-1024 encapsulation key length.
pub const EK_PQ_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length.
pub const CT_PQ_LEN: usize = 1568;
/// Uncompressed P-384 point length.
pub const T_LEN: usize = 97;
/// Encapsulation key length.
pub const EK_LEN: usize = EK_PQ_LEN + T_LEN;
/// Ciphertext (HPKE `enc`) length.
pub const CT_LEN: usize = CT_PQ_LEN + T_LEN;
/// Shared secret length.
pub const SS_LEN: usize = 32;
/// Length of the encapsulation randomness: `mlkem_random (32) || p384_seed (48)`.
pub const RANDOMNESS_LEN: usize = 80;
/// Domain-separation label of the combiner.
pub const LABEL: &[u8] = b"MLKEM1024-P384";

const SEED_PQ_LEN: usize = 64;
const SEED_T_LEN: usize = 48;

/// Expanded decapsulation key (derived from the seed).
struct ExpandedKey {
    dk_pq: DecapsulationKey,
    dk_t: NonZeroScalar,
    ek: Vec<u8>,
    ek_t: Vec<u8>,
}

fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// `RandomScalar_P384`: rejection sampling over 48-byte blocks. Returns
/// `None` if the first block is out of range (probability < 2^-192).
fn scalar_from_block(block: &[u8]) -> Option<NonZeroScalar> {
    debug_assert_eq!(block.len(), SEED_T_LEN);
    let fb = FieldBytes::try_from(block).ok()?;
    Option::from(NonZeroScalar::from_repr(fb))
}

/// RandomScalar for DeriveKeyPair. If the 48-byte `seed_T` is out of range
/// (cryptographically negligible), further blocks are drawn as
/// `SHAKE256(seed_T || counter)[0:48]` with a one-byte counter starting at 1.
fn random_scalar_derive(seed_t: &[u8]) -> Result<NonZeroScalar> {
    if let Some(s) = scalar_from_block(seed_t) {
        return Ok(s);
    }
    for counter in 1u8..=255 {
        let mut block = [0u8; SEED_T_LEN];
        shake256(&[seed_t, &[counter]], &mut block);
        if let Some(s) = scalar_from_block(&block) {
            return Ok(s);
        }
    }
    Err(Error::InvalidKey("P-384 scalar derivation failed"))
}

fn point_bytes(pk: &PublicKey) -> Vec<u8> {
    Sec1Point::from(pk).as_bytes().to_vec()
}

fn parse_point(bytes: &[u8]) -> Result<PublicKey> {
    // Only uncompressed encodings (0x04 || X || Y) are valid.
    if bytes.len() != T_LEN || bytes[0] != 0x04 {
        return Err(Error::Format("invalid P-384 point encoding"));
    }
    // Validates on-curve and rejects the identity.
    PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::Format("invalid P-384 point"))
}

fn expand(seed: &[u8; SEED_LEN]) -> Result<ExpandedKey> {
    let mut full = Zeroizing::new([0u8; SEED_PQ_LEN + SEED_T_LEN]);
    shake256(&[seed], &mut *full);
    let (seed_pq, seed_t) = full.split_at(SEED_PQ_LEN);

    let pq_seed = MlKemSeed::try_from(seed_pq).expect("64 bytes");
    let dk_pq = DecapsulationKey::from_seed(pq_seed);
    let ek_pq = dk_pq.encapsulation_key().to_bytes();

    let dk_t = random_scalar_derive(seed_t)?;
    let ek_t_pk = PublicKey::from_secret_scalar(&dk_t);
    let ek_t = point_bytes(&ek_t_pk);

    let mut ek = Vec::with_capacity(EK_LEN);
    ek.extend_from_slice(ek_pq.as_slice());
    ek.extend_from_slice(&ek_t);
    debug_assert_eq!(ek.len(), EK_LEN);
    Ok(ExpandedKey {
        dk_pq,
        dk_t,
        ek,
        ek_t,
    })
}

/// DeriveKeyPair: returns `(dk, ek)` where `dk` is the seed itself (kept as
/// the 32-byte stored form) and `ek` is the 1665-byte encapsulation key.
pub fn derive_key_pair(seed: &[u8; SEED_LEN]) -> Result<(Zeroizing<[u8; SEED_LEN]>, Vec<u8>)> {
    let ex = expand(seed)?;
    Ok((Zeroizing::new(*seed), ex.ek.clone()))
}

/// Generate a fresh random 32-byte seed.
pub fn generate_seed() -> Result<Zeroizing<[u8; SEED_LEN]>> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    getrandom::fill(&mut *seed).map_err(|_| Error::Io("random number generator failure".into()))?;
    Ok(seed)
}

/// Validate a 1665-byte encapsulation key: well-formed ML-KEM-1024 key and a
/// valid, non-identity uncompressed P-384 point.
pub fn validate_ek(ek: &[u8]) -> Result<()> {
    split_ek(ek).map(|_| ())
}

fn split_ek(ek: &[u8]) -> Result<(EncapsulationKey, PublicKey)> {
    if ek.len() != EK_LEN {
        return Err(Error::InvalidKey("invalid encapsulation key length"));
    }
    let (pq, t) = ek.split_at(EK_PQ_LEN);
    let pq_arr = ml_kem::Key::<EncapsulationKey>::try_from(pq).expect("1568 bytes");
    let ek_pq = EncapsulationKey::new(&pq_arr)
        .map_err(|_| Error::InvalidKey("invalid ML-KEM encapsulation key"))?;
    let ek_t = parse_point(t).map_err(|_| Error::InvalidKey("invalid P-384 public key"))?;
    Ok((ek_pq, ek_t))
}

fn combiner(ss_pq: &[u8], ss_t: &[u8], ct_t: &[u8], ek_t: &[u8]) -> Zeroizing<[u8; SS_LEN]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_pq);
    Digest::update(&mut h, ss_t);
    Digest::update(&mut h, ct_t);
    Digest::update(&mut h, ek_t);
    Digest::update(&mut h, LABEL);
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; SS_LEN]);
    out.copy_from_slice(&digest);
    out
}

/// Derandomized encapsulation (`EncapsDerand`).
///
/// `randomness = mlkem_random (32) || p384_seed (48)`. Intended for test
/// vectors; the randomness MUST be uniformly random in production use.
fn encapsulate_derand(
    ek: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<(Zeroizing<[u8; SS_LEN]>, Vec<u8>)> {
    let (ek_pq, ek_t_pk) = split_ek(ek)?;
    let (m, p384_seed) = randomness.split_at(32);

    let m = ml_kem::B32::try_from(m).expect("32 bytes");
    let (ct_pq, ss_pq) = ek_pq.encapsulate_deterministic(&m);
    let ss_pq = Zeroizing::new(ss_pq);

    // RandomScalar(p384_seed): a single 48-byte draw; reject if 0 or >= n.
    let sk_e =
        scalar_from_block(p384_seed).ok_or(Error::Format("P-384 ephemeral scalar out of range"))?;
    let ct_t = point_bytes(&PublicKey::from_secret_scalar(&sk_e));
    let shared = ecdh::diffie_hellman(&sk_e, ek_t_pk.as_affine());
    let ss_t = Zeroizing::new(shared.raw_secret_bytes().to_vec());

    let ek_t = &ek[EK_PQ_LEN..];
    let ss = combiner(ss_pq.as_slice(), &ss_t, &ct_t, ek_t);

    let mut ct = Vec::with_capacity(CT_LEN);
    ct.extend_from_slice(ct_pq.as_slice());
    ct.extend_from_slice(&ct_t);
    Ok((ss, ct))
}

/// Derandomized encapsulation, exposed for test vectors only.
#[cfg(any(test, feature = "hazmat"))]
pub fn encapsulate_deterministic(
    ek: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<(Zeroizing<[u8; SS_LEN]>, Vec<u8>)> {
    encapsulate_derand(ek, randomness)
}

/// `Encaps(ek)`: returns `(ss, ct)` using fresh OS randomness.
///
/// The returned `ct` is the HPKE `enc` (1665 bytes).
pub fn encapsulate(ek: &[u8]) -> Result<(Zeroizing<[u8; SS_LEN]>, Vec<u8>)> {
    let mut r = Zeroizing::new([0u8; RANDOMNESS_LEN]);
    // A P-384 draw out of range has probability < 2^-190; retry anyway.
    for _ in 0..8 {
        getrandom::fill(&mut *r)
            .map_err(|_| Error::Io("random number generator failure".into()))?;
        match encapsulate_derand(ek, &r) {
            Err(Error::Format("P-384 ephemeral scalar out of range")) => continue,
            other => return other,
        }
    }
    Err(Error::Format("encapsulation failed"))
}

/// `Decaps(dk, ct)` with the 32-byte seed form of the decapsulation key.
pub fn decapsulate(seed: &[u8; SEED_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; SS_LEN]>> {
    if ct.len() != CT_LEN {
        return Err(Error::Format("invalid KEM ciphertext length"));
    }
    let ex = expand(seed)?;
    let (ct_pq_b, ct_t_b) = ct.split_at(CT_PQ_LEN);
    let ct_pq = Ciphertext::try_from(ct_pq_b).expect("1568 bytes");
    let ss_pq = Zeroizing::new(ex.dk_pq.decapsulate(&ct_pq));

    let ct_t_pk = parse_point(ct_t_b)?;
    let shared = ecdh::diffie_hellman(&ex.dk_t, ct_t_pk.as_affine());
    let ss_t = Zeroizing::new(shared.raw_secret_bytes().to_vec());

    Ok(combiner(ss_pq.as_slice(), &ss_t, ct_t_b, &ex.ek_t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        seed: String,
        randomness: String,
        encapsulation_key: String,
        decapsulation_key: String,
        ciphertext: String,
        shared_secret: String,
        decapsulation_key_pq: String,
        decapsulation_key_t: String,
    }
    #[derive(Deserialize)]
    struct File {
        vectors: Vec<Vector>,
    }

    fn load() -> File {
        let p = crate::test_util::vector_path("mlkem1024p384.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[test]
    fn derive_key_pair_vectors() {
        let f = load();
        assert!(!f.vectors.is_empty());
        for v in &f.vectors {
            let seed: [u8; 32] = arr(&v.seed);
            assert_eq!(v.decapsulation_key, v.seed);
            let (dk, ek) = derive_key_pair(&seed).unwrap();
            assert_eq!(&dk[..], &seed[..]);
            assert_eq!(hex::encode(&ek), v.encapsulation_key);

            // seed expansion matches the published intermediate values
            let mut full = [0u8; 112];
            shake256(&[&seed], &mut full);
            assert_eq!(hex::encode(&full[..64]), v.decapsulation_key_pq);
            assert_eq!(hex::encode(&full[64..]), v.decapsulation_key_t);
        }
    }

    #[test]
    fn encaps_derand_vectors() {
        for v in &load().vectors {
            let ek = hex::decode(&v.encapsulation_key).unwrap();
            let r: [u8; RANDOMNESS_LEN] = arr(&v.randomness);
            let (ss, ct) = encapsulate_deterministic(&ek, &r).unwrap();
            assert_eq!(hex::encode(&ct), v.ciphertext);
            assert_eq!(hex::encode(*ss), v.shared_secret);
        }
    }

    #[test]
    fn decaps_vectors() {
        for v in &load().vectors {
            let seed: [u8; 32] = arr(&v.seed);
            let ct = hex::decode(&v.ciphertext).unwrap();
            let ss = decapsulate(&seed, &ct).unwrap();
            assert_eq!(hex::encode(*ss), v.shared_secret);
        }
    }

    #[test]
    fn random_roundtrip_and_sizes() {
        let seed = generate_seed().unwrap();
        let (_, ek) = derive_key_pair(&seed).unwrap();
        assert_eq!(ek.len(), EK_LEN);
        validate_ek(&ek).unwrap();
        let (ss1, ct) = encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), CT_LEN);
        let (ss2, ct2) = encapsulate(&ek).unwrap();
        assert_ne!(ct, ct2);
        assert_ne!(*ss1, *ss2);
        assert_eq!(*decapsulate(&seed, &ct).unwrap(), *ss1);
        assert_eq!(*decapsulate(&seed, &ct2).unwrap(), *ss2);
    }

    #[test]
    fn invalid_inputs_rejected() {
        let seed = [5u8; 32];
        let (_, ek) = derive_key_pair(&seed).unwrap();
        let (_, ct) = encapsulate(&ek).unwrap();

        assert!(validate_ek(&ek[..EK_LEN - 1]).is_err());
        // compressed-tag / off-curve / identity points in ek_T
        let mut bad = ek.clone();
        bad[EK_PQ_LEN] = 0x02;
        assert!(validate_ek(&bad).is_err());
        let mut bad = ek.clone();
        bad[EK_LEN - 1] ^= 1; // off curve
        assert!(validate_ek(&bad).is_err());
        let mut bad = ek.clone();
        for b in &mut bad[EK_PQ_LEN..] {
            *b = 0;
        }
        assert!(validate_ek(&bad).is_err());

        // ct length / bad ct_T
        assert!(decapsulate(&seed, &ct[..CT_LEN - 1]).is_err());
        let mut bad = ct.clone();
        bad[CT_PQ_LEN] = 0x03;
        assert!(decapsulate(&seed, &bad).is_err());
        let mut bad = ct.clone();
        bad[CT_LEN - 1] ^= 1;
        assert!(decapsulate(&seed, &bad).is_err());

        // tampered ct_PQ => implicit rejection gives a different secret
        let (ss, _) = (decapsulate(&seed, &ct).unwrap(), ());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_ne!(*decapsulate(&seed, &bad).unwrap(), *ss);
        // wrong key => different secret
        assert_ne!(*decapsulate(&[6u8; 32], &ct).unwrap(), *ss);

        // randomness with out-of-range scalar
        let mut r = [0xffu8; RANDOMNESS_LEN];
        r[..32].copy_from_slice(&[1u8; 32]);
        assert!(encapsulate_deterministic(&ek, &r).is_err());
        let mut r = [0u8; RANDOMNESS_LEN];
        r[..32].copy_from_slice(&[1u8; 32]);
        assert!(encapsulate_deterministic(&ek, &r).is_err());
    }
}
