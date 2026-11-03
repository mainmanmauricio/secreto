//! Hand-rolled Bech32 (BIP 173 charset and polymod) **without** the 90
//! character limit. Strings are limited to 8192 characters instead
//! (`spec/format.md`, *Limits*).
//!
//! The HRP is emitted exactly as given. The checksum is always computed over
//! the lower-cased HRP, so secret keys can use an upper-case HRP and an
//! all-upper-case encoding. Mixed-case strings are rejected on decode.

use crate::error::{Error, Result};

/// Maximum accepted Bech32 string length (characters).
pub const MAX_LEN: usize = 8192;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp_lower: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp_lower.len() * 2 + 1);
    v.extend(hrp_lower.iter().map(|b| b >> 5));
    v.push(0);
    v.extend(hrp_lower.iter().map(|b| b & 31));
    v
}

fn checksum(hrp_lower: &[u8], data5: &[u8]) -> [u8; 6] {
    let vals = hrp_expand(hrp_lower)
        .into_iter()
        .chain(data5.iter().copied())
        .chain([0u8; 6]);
    let m = polymod(vals) ^ 1;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((m >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

/// Regroup bits. `from`/`to` are bit widths.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &b in data {
        if u32::from(b) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(b);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        // Leftover bits must be fewer than a full source group, and zero.
        return None;
    }
    Some(out)
}

/// Encode `data` with the given human readable part.
///
/// The case of `hrp` determines the case of the entire output. `hrp` must
/// be non-empty, printable ASCII (33..=126) and not mixed-case.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
    validate_hrp(hrp)?;
    let has_upper = hrp.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = hrp.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return Err(Error::InvalidKey("bech32: mixed-case HRP"));
    }
    let hrp_lower = hrp.to_ascii_lowercase();
    let data5 = convert_bits(data, 8, 5, true).expect("8->5 with padding cannot fail");
    let ck = checksum(hrp_lower.as_bytes(), &data5);

    let mut s = String::with_capacity(hrp.len() + 1 + data5.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &v in data5.iter().chain(ck.iter()) {
        s.push(CHARSET[v as usize] as char);
    }
    if has_upper {
        s.make_ascii_uppercase();
    }
    if s.len() > MAX_LEN {
        return Err(Error::InvalidKey("bech32: string too long"));
    }
    Ok(s)
}

fn validate_hrp(hrp: &str) -> Result<()> {
    if hrp.is_empty() || !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::InvalidKey("bech32: invalid HRP"));
    }
    Ok(())
}

/// Decode a Bech32 string, returning the HRP (in the case it was written)
/// and the data bytes.
pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
    const ERR: &str = "bech32: invalid encoding";
    if s.len() > MAX_LEN {
        return Err(Error::InvalidKey("bech32: string too long"));
    }
    if !s.is_ascii() || !s.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::InvalidKey(ERR));
    }
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return Err(Error::InvalidKey("bech32: mixed case"));
    }
    let lower = s.to_ascii_lowercase();
    let sep = lower.rfind('1').ok_or(Error::InvalidKey(ERR))?;
    if sep == 0 || lower.len() - sep - 1 < 6 {
        return Err(Error::InvalidKey(ERR));
    }
    let hrp_lower = &lower.as_bytes()[..sep];
    let mut data5 = Vec::with_capacity(lower.len() - sep - 1);
    for c in lower.bytes().skip(sep + 1) {
        let idx = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(Error::InvalidKey(ERR))?;
        data5.push(idx as u8);
    }
    let vals = hrp_expand(hrp_lower)
        .into_iter()
        .chain(data5.iter().copied());
    if polymod(vals) != 1 {
        return Err(Error::InvalidKey("bech32: bad checksum"));
    }
    data5.truncate(data5.len() - 6);
    let data = convert_bits(&data5, 5, 8, false).ok_or(Error::InvalidKey("bech32: bad padding"))?;
    Ok((s[..sep].to_string(), data))
}

/// Decode and require an exact HRP (case-sensitive) and data length.
pub fn decode_exact(s: &str, hrp: &str, len: usize) -> Result<Vec<u8>> {
    let (h, data) = decode(s)?;
    if h != hrp {
        return Err(Error::InvalidKey("bech32: unexpected HRP"));
    }
    if data.len() != len {
        return Err(Error::InvalidKey("bech32: unexpected data length"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        hrp: String,
        data_hex: String,
        encoded: String,
    }
    #[derive(Deserialize)]
    struct Invalid {
        encoded: String,
        reason: String,
    }
    #[derive(Deserialize)]
    struct File {
        vectors: Vec<Vector>,
        invalid: Vec<Invalid>,
    }

    fn load() -> File {
        let p = crate::test_util::vector_path("bech32.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn vectors_roundtrip() {
        for v in load().vectors {
            let data = hex::decode(&v.data_hex).unwrap();
            assert_eq!(encode(&v.hrp, &data).unwrap(), v.encoded);
            let (hrp, d) = decode(&v.encoded).unwrap();
            assert_eq!(hrp, v.hrp);
            assert_eq!(d, data);
        }
    }

    #[test]
    fn invalid_vectors() {
        for v in load().invalid {
            assert!(decode(&v.encoded).is_err(), "{}: {}", v.reason, v.encoded);
        }
    }

    #[test]
    fn long_strings_beyond_90_chars() {
        let data: Vec<u8> = (0..1665u32).map(|i| (i * 7) as u8).collect();
        let s = encode("secreto", &data).unwrap();
        assert!(s.len() > 90);
        let (h, d) = decode(&s).unwrap();
        assert_eq!(h, "secreto");
        assert_eq!(d, data);
        assert_eq!(decode_exact(&s, "secreto", 1665).unwrap(), data);
        assert!(decode_exact(&s, "SECRETO", 1665).is_err());
        assert!(decode_exact(&s, "secreto", 1664).is_err());
    }

    #[test]
    fn rejects_bad_padding_and_limits() {
        // Flip a data character so the checksum fails.
        let s = encode("secreto", &[1, 2, 3]).unwrap();
        let mut b = s.into_bytes();
        let n = b.len();
        b[n - 7] = if b[n - 7] == b'q' { b'p' } else { b'q' };
        assert!(decode(std::str::from_utf8(&b).unwrap()).is_err());
        assert!(decode("").is_err());
        assert!(decode("1qqqqqq").is_err());
        assert!(decode("secreto1").is_err());
        let huge = "a".repeat(MAX_LEN + 1);
        assert!(decode(&huge).is_err());
    }

    #[test]
    fn empty_data() {
        let s = encode("secreto", &[]).unwrap();
        assert_eq!(decode(&s).unwrap().1, Vec::<u8>::new());
    }
}
