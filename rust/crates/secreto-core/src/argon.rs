//! Passphrase recipient: Argon2id wrap of the file key
//! (`spec/format.md`, *Recipient type: argon2id*).

use crate::error::{Error, Result};
use crate::header::{Stanza, TYPE_ARGON2ID};
use argon2::{Algorithm, Argon2, AssociatedData, Params, ParamsBuilder, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use zeroize::Zeroizing;

/// Salt length (bytes).
pub const SALT_LEN: usize = 16;
/// Wrapped file key length: 32 bytes plus the 16-byte tag.
pub const BODY_LEN: usize = 48;
/// Wrap key length.
pub const KEY_LEN: usize = 32;
/// Prefix of the Argon2 salt.
pub const SALT_PREFIX: &[u8] = b"secreto/v1/argon2id";

/// Encryption default memory cost (KiB).
pub const DEFAULT_M_KIB: u32 = 1_048_576;
/// Encryption default time cost.
pub const DEFAULT_T: u32 = 3;
/// Encryption default parallelism.
pub const DEFAULT_P: u32 = 4;

/// Decryption acceptance range for `m_kib`.
pub const M_KIB_RANGE: (u32, u32) = (65_536, 4_194_304);
/// Decryption acceptance range for `t`.
pub const T_RANGE: (u32, u32) = (3, 16);
/// Decryption acceptance range for `p`.
pub const P_RANGE: (u32, u32) = (1, 16);

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgonParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl ArgonParams {
    /// Parameters mandated for encryption.
    pub const DEFAULT: ArgonParams = ArgonParams {
        m_kib: DEFAULT_M_KIB,
        t: DEFAULT_T,
        p: DEFAULT_P,
    };

    /// Are the parameters inside the decryption acceptance range?
    pub fn in_decrypt_range(&self) -> bool {
        (M_KIB_RANGE.0..=M_KIB_RANGE.1).contains(&self.m_kib)
            && (T_RANGE.0..=T_RANGE.1).contains(&self.t)
            && (P_RANGE.0..=P_RANGE.1).contains(&self.p)
    }
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Raw Argon2id (RFC 9106), with optional secret and associated data. Used
/// for component vectors.
pub fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    params: ArgonParams,
    tag_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    const E: Error = Error::Format("invalid Argon2 parameters");
    let mut b = ParamsBuilder::new();
    b.m_cost(params.m_kib)
        .t_cost(params.t)
        .p_cost(params.p)
        .output_len(tag_len);
    if !ad.is_empty() {
        b.data(AssociatedData::new(ad).map_err(|_| E)?);
    }
    let p: Params = b.build().map_err(|_| E)?;
    let a = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, p).map_err(|_| E)?
    };
    let mut out = Zeroizing::new(vec![0u8; tag_len]);
    a.hash_password_into(password, salt, &mut out)
        .map_err(|_| E)?;
    Ok(out)
}

/// Derive the 32-byte wrap key: `Argon2id(P, S = prefix || salt, m, t, p, 32)`.
pub fn derive_wrap_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: ArgonParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut s = Vec::with_capacity(SALT_PREFIX.len() + SALT_LEN);
    s.extend_from_slice(SALT_PREFIX);
    s.extend_from_slice(salt);
    let raw = argon2id_raw(passphrase, &s, &[], &[], params, KEY_LEN)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&raw);
    Ok(key)
}

fn zero_nonce() -> [u8; 12] {
    [0u8; 12]
}

/// Wrap `file_key` with explicit salt and parameters (used by tests and by
/// [`wrap`]).
pub fn wrap_with(
    passphrase: &[u8],
    file_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    params: ArgonParams,
) -> Result<Stanza> {
    let key = derive_wrap_key(passphrase, salt, params)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let body = cipher
        .encrypt((&zero_nonce()).into(), file_key.as_slice())
        .map_err(|_| Error::Format("AEAD failure"))?;
    debug_assert_eq!(body.len(), BODY_LEN);
    Ok(Stanza {
        args: vec![
            TYPE_ARGON2ID.to_string(),
            STANDARD_NO_PAD.encode(salt),
            params.m_kib.to_string(),
            params.t.to_string(),
            params.p.to_string(),
        ],
        body,
    })
}

/// Wrap `file_key` with a fresh salt and the mandated parameters
/// (`m=1 GiB, t=3, p=4`).
pub fn wrap(passphrase: &[u8], file_key: &[u8; 32]) -> Result<Stanza> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::Io("random number generator failure".into()))?;
    wrap_with(passphrase, file_key, &salt, ArgonParams::DEFAULT)
}

/// Parse a canonical decimal integer (`^[1-9][0-9]*$`) fitting in `u32`.
fn parse_canonical_u32(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse().ok()
}

/// Parse and validate an argon2id stanza (argument count, canonical
/// numbers, parameter ranges, salt, body length). Does **not** run Argon2.
pub fn parse_stanza(stanza: &Stanza) -> Result<([u8; SALT_LEN], ArgonParams)> {
    const E: Error = Error::Format("invalid argon2id stanza");
    if stanza.kind() != TYPE_ARGON2ID || stanza.args.len() != 5 {
        return Err(E);
    }
    let salt = STANDARD_NO_PAD.decode(&stanza.args[1]).map_err(|_| E)?;
    let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| E)?;
    let params = ArgonParams {
        m_kib: parse_canonical_u32(&stanza.args[2]).ok_or(E)?,
        t: parse_canonical_u32(&stanza.args[3]).ok_or(E)?,
        p: parse_canonical_u32(&stanza.args[4]).ok_or(E)?,
    };
    if !params.in_decrypt_range() {
        return Err(Error::Format("argon2id parameters out of range"));
    }
    if stanza.body.len() != BODY_LEN {
        return Err(E);
    }
    Ok((salt, params))
}

/// Unwrap the file key from an argon2id stanza.
///
/// Returns [`Error::Format`] for malformed stanzas and [`Error::NoMatch`]
/// for a wrong passphrase.
pub fn unwrap(stanza: &Stanza, passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let (salt, params) = parse_stanza(stanza)?;
    let key = derive_wrap_key(passphrase, &salt, params)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let pt = cipher
        .decrypt((&zero_nonce()).into(), stanza.body.as_slice())
        .map_err(|_| Error::NoMatch)?;
    let pt = Zeroizing::new(pt);
    let mut fk = Zeroizing::new([0u8; 32]);
    if pt.len() != 32 {
        return Err(Error::Format("invalid file key length"));
    }
    fk.copy_from_slice(&pt);
    Ok(fk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct V {
        password: String,
        salt: String,
        secret: String,
        ad: String,
        m_kib: u32,
        t: u32,
        p: u32,
        tag_length: usize,
        tag: String,
    }
    #[derive(Deserialize)]
    struct File {
        vectors: Vec<V>,
    }

    #[test]
    fn rfc9106_vectors() {
        let p = crate::test_util::vector_path("argon2id.json");
        let f: File = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert!(f.vectors.len() >= 2);
        for v in f.vectors {
            let out = argon2id_raw(
                &hex::decode(&v.password).unwrap(),
                &hex::decode(&v.salt).unwrap(),
                &hex::decode(&v.secret).unwrap(),
                &hex::decode(&v.ad).unwrap(),
                ArgonParams {
                    m_kib: v.m_kib,
                    t: v.t,
                    p: v.p,
                },
                v.tag_length,
            )
            .unwrap();
            assert_eq!(hex::encode(&*out), v.tag);
        }
    }

    const LOW: ArgonParams = ArgonParams {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };

    #[test]
    fn wrap_unwrap_roundtrip() {
        let fk = [0x5au8; 32];
        let st = wrap_with(b"correct horse", &fk, &[1u8; 16], LOW).unwrap();
        assert_eq!(st.args.len(), 5);
        assert_eq!(st.args[0], "argon2id");
        assert_eq!(st.args[2], "65536");
        assert_eq!(st.body.len(), BODY_LEN);
        assert_eq!(&*unwrap(&st, b"correct horse").unwrap(), &fk);
        assert_eq!(unwrap(&st, b"wrong").unwrap_err(), Error::NoMatch);
    }

    #[test]
    fn stanza_validation() {
        let fk = [1u8; 32];
        let good = wrap_with(b"pw", &fk, &[2u8; 16], LOW).unwrap();
        assert!(parse_stanza(&good).is_ok());

        let mutate = |f: &dyn Fn(&mut Stanza)| {
            let mut s = good.clone();
            f(&mut s);
            parse_stanza(&s)
        };
        // argument count
        assert!(mutate(&|s| s.args.pop().map(|_| ()).unwrap()).is_err());
        assert!(mutate(&|s| s.args.push("1".into())).is_err());
        // non-canonical numbers
        assert!(mutate(&|s| s.args[2] = "065536".into()).is_err());
        assert!(mutate(&|s| s.args[3] = "+3".into()).is_err());
        assert!(mutate(&|s| s.args[3] = "03".into()).is_err());
        assert!(mutate(&|s| s.args[4] = "0".into()).is_err());
        assert!(mutate(&|s| s.args[4] = "".into()).is_err());
        assert!(mutate(&|s| s.args[2] = "99999999999999999999".into()).is_err());
        // out of range
        assert!(mutate(&|s| s.args[2] = "65535".into()).is_err());
        assert!(mutate(&|s| s.args[2] = "4194305".into()).is_err());
        assert!(mutate(&|s| s.args[3] = "2".into()).is_err());
        assert!(mutate(&|s| s.args[3] = "17".into()).is_err());
        assert!(mutate(&|s| s.args[4] = "17".into()).is_err());
        // salt
        assert!(mutate(&|s| s.args[1] = "AAAA".into()).is_err());
        assert!(mutate(&|s| s.args[1].push('=')).is_err());
        // body length
        assert!(mutate(&|s| s.body.pop().map(|_| ()).unwrap()).is_err());
        assert!(mutate(&|s| s.body.push(0)).is_err());
        // type
        assert!(mutate(&|s| s.args[0] = "scrypt".into()).is_err());
        // edges accepted
        assert!(mutate(&|s| s.args[2] = "4194304".into()).is_ok());
        assert!(mutate(&|s| s.args[3] = "16".into()).is_ok());
        assert!(mutate(&|s| s.args[4] = "16".into()).is_ok());
    }

    #[test]
    fn tampered_body_is_no_match() {
        let fk = [1u8; 32];
        let mut st = wrap_with(b"pw", &fk, &[2u8; 16], LOW).unwrap();
        st.body[0] ^= 1;
        assert_eq!(unwrap(&st, b"pw").unwrap_err(), Error::NoMatch);
    }

    #[test]
    fn default_params_are_mandated_values() {
        assert_eq!(
            ArgonParams::DEFAULT,
            ArgonParams {
                m_kib: 1_048_576,
                t: 3,
                p: 4
            }
        );
        assert!(ArgonParams::DEFAULT.in_decrypt_range());
    }
}
