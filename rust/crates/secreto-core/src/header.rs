//! Header parsing, serialization and MAC (`spec/format.md`, *Header*).

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

/// Version line, including the LF.
pub const VERSION_LINE: &str = "secreto/v1\n";
/// Maximum header size in bytes.
pub const MAX_HEADER_SIZE: usize = 1 << 20;
/// Maximum number of stanzas.
pub const MAX_STANZAS: usize = 256;
/// Maximum header line length, excluding LF.
pub const MAX_LINE_LEN: usize = 4096;
/// HKDF info for the header MAC key.
pub const MAC_INFO: &[u8] = b"secreto/v1/header";
/// Length of the header MAC.
pub const MAC_LEN: usize = 64;
/// Stanza body columns.
pub const BODY_COLS: usize = 64;

/// Type tag of the mlkem1024p384 recipient stanza.
pub const TYPE_MLKEM: &str = "mlkem1024p384";
/// Type tag of the argon2id passphrase stanza.
pub const TYPE_ARGON2ID: &str = "argon2id";

/// A recipient stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stanza {
    /// Space-separated arguments; `args[0]` is the stanza type.
    pub args: Vec<String>,
    /// Decoded body.
    pub body: Vec<u8>,
}

impl Stanza {
    /// Stanza type tag.
    pub fn kind(&self) -> &str {
        &self.args[0]
    }
}

/// A parsed header.
#[derive(Debug, Clone)]
pub struct Header {
    /// Recipient stanzas, in order.
    pub stanzas: Vec<Stanza>,
    /// The MAC from the final line.
    pub mac: [u8; MAC_LEN],
    /// Header bytes covered by the MAC (through the three hyphens).
    pub mac_input: Vec<u8>,
}

/// Derive the 64-byte header MAC key from the file key.
pub fn mac_key(file_key: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let hk = Hkdf::<Sha512>::new(None, file_key);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(MAC_INFO, &mut *out).expect("64 <= 255 * 64");
    out
}

/// HMAC-SHA-512 over `mac_input` (the header through `---`).
pub fn compute_mac(file_key: &[u8; 32], mac_input: &[u8]) -> [u8; MAC_LEN] {
    let key = mac_key(file_key);
    let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(&*key).expect("any key length");
    m.update(mac_input);
    let tag = m.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Verify the header MAC in constant time.
pub fn verify_mac(file_key: &[u8; 32], header: &Header) -> Result<()> {
    let key = mac_key(file_key);
    let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(&*key).expect("any key length");
    m.update(&header.mac_input);
    m.verify_slice(&header.mac)
        .map_err(|_| Error::Format("header MAC verification failed"))
}

fn valid_arg(a: &str) -> bool {
    !a.is_empty() && a.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Serialize the stanzas and the `---` prefix (the MAC input). Does not
/// include the MAC value.
pub fn marshal_prefix(stanzas: &[Stanza]) -> Result<Vec<u8>> {
    if stanzas.is_empty() || stanzas.len() > MAX_STANZAS {
        return Err(Error::Format("invalid stanza count"));
    }
    let mut out = Vec::new();
    out.extend_from_slice(VERSION_LINE.as_bytes());
    for s in stanzas {
        if s.args.is_empty() || !s.args.iter().all(|a| valid_arg(a)) {
            return Err(Error::Format("invalid stanza argument"));
        }
        let mut line = String::from("->");
        for a in &s.args {
            line.push(' ');
            line.push_str(a);
        }
        if line.len() > MAX_LINE_LEN {
            return Err(Error::Format("header line too long"));
        }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
        let b64 = STANDARD_NO_PAD.encode(&s.body);
        let mut rest = b64.as_bytes();
        while rest.len() >= BODY_COLS {
            out.extend_from_slice(&rest[..BODY_COLS]);
            out.push(b'\n');
            rest = &rest[BODY_COLS..];
        }
        // Final line is always < 64 chars, possibly empty.
        out.extend_from_slice(rest);
        out.push(b'\n');
    }
    out.extend_from_slice(b"---");
    if out.len() > MAX_HEADER_SIZE {
        return Err(Error::Format("header too large"));
    }
    Ok(out)
}

/// Serialize a complete header (stanzas + MAC line). Returns the header
/// bytes and the MAC.
pub fn marshal(stanzas: &[Stanza], file_key: &[u8; 32]) -> Result<(Vec<u8>, [u8; MAC_LEN])> {
    let mut out = marshal_prefix(stanzas)?;
    let mac = compute_mac(file_key, &out);
    out.push(b' ');
    out.extend_from_slice(STANDARD_NO_PAD.encode(mac).as_bytes());
    out.push(b'\n');
    Ok((out, mac))
}

const F: Error = Error::Format("malformed header");

/// Parse a header from the start of `data`. Returns the header and the
/// number of header bytes consumed (the payload starts at that offset).
pub fn parse(data: &[u8]) -> Result<(Header, usize)> {
    let mut pos = 0usize;

    let next_line = |pos: &mut usize| -> Result<&[u8]> {
        let rest = &data[*pos..];
        let limit = rest.len().min(MAX_LINE_LEN + 1);
        match rest[..limit].iter().position(|&b| b == b'\n') {
            Some(i) => {
                let line = &rest[..i];
                *pos += i + 1;
                if *pos > MAX_HEADER_SIZE {
                    return Err(Error::Format("header too large"));
                }
                Ok(line)
            }
            None if rest.len() > MAX_LINE_LEN => Err(Error::Format("header line too long")),
            None => Err(F),
        }
    };

    if next_line(&mut pos)? != VERSION_LINE.trim_end().as_bytes() {
        return Err(Error::Format("unsupported version"));
    }

    let mut stanzas: Vec<Stanza> = Vec::new();
    let mac_input_end;
    let mac: [u8; MAC_LEN];

    loop {
        let line_start = pos;
        let line = next_line(&mut pos)?;
        if let Some(rest) = line.strip_prefix(b"-> ") {
            if stanzas.len() >= MAX_STANZAS {
                return Err(Error::Format("too many stanzas"));
            }
            let text = std::str::from_utf8(rest).map_err(|_| F)?;
            let args: Vec<String> = text.split(' ').map(str::to_owned).collect();
            if !args.iter().all(|a| valid_arg(a)) {
                return Err(F);
            }
            let mut b64 = Vec::new();
            loop {
                let l = next_line(&mut pos)?;
                if l.len() > BODY_COLS || !l.iter().all(is_b64_char) {
                    return Err(F);
                }
                b64.extend_from_slice(l);
                if l.len() < BODY_COLS {
                    break;
                }
            }
            let body = STANDARD_NO_PAD.decode(&b64).map_err(|_| F)?;
            stanzas.push(Stanza { args, body });
        } else if let Some(rest) = line.strip_prefix(b"--- ") {
            if stanzas.is_empty() {
                return Err(Error::Format("no stanzas"));
            }
            if rest.len() != 86 || !rest.iter().all(is_b64_char) {
                return Err(F);
            }
            let raw = STANDARD_NO_PAD.decode(rest).map_err(|_| F)?;
            mac = raw.try_into().map_err(|_| F)?;
            mac_input_end = line_start + 3;
            break;
        } else {
            return Err(F);
        }
    }

    validate_stanza_set(&stanzas)?;
    Ok((
        Header {
            stanzas,
            mac,
            mac_input: data[..mac_input_end].to_vec(),
        },
        pos,
    ))
}

fn is_b64_char(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'
}

/// argon2id must be the only stanza when present.
fn validate_stanza_set(stanzas: &[Stanza]) -> Result<()> {
    if stanzas.iter().any(|s| s.kind() == TYPE_ARGON2ID) && stanzas.len() != 1 {
        return Err(Error::Format("argon2id stanza must be the only stanza"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(args: &[&str], body: Vec<u8>) -> Stanza {
        Stanza {
            args: args.iter().map(|s| s.to_string()).collect(),
            body,
        }
    }

    #[test]
    fn mac_key_matches_manual_hkdf() {
        // HKDF-SHA-512 with empty salt: cross-check via a manual HMAC chain.
        let fk = [0x11u8; 32];
        let prk = {
            let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(&[0u8; 64]).unwrap();
            m.update(&fk);
            m.finalize().into_bytes()
        };
        let okm = {
            let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(&prk).unwrap();
            m.update(MAC_INFO);
            m.update(&[1u8]);
            m.finalize().into_bytes()
        };
        assert_eq!(&mac_key(&fk)[..], &okm[..]);
    }

    #[test]
    fn roundtrip_various_body_sizes() {
        let fk = [7u8; 32];
        for n in [0usize, 1, 47, 48, 49, 96, 100, 1665] {
            let st = vec![
                stanza(&["x", "arg"], (0..n).map(|i| i as u8).collect()),
                stanza(&["y"], vec![]),
            ];
            let (bytes, mac) = marshal(&st, &fk).unwrap();
            let mut with_payload = bytes.clone();
            with_payload.extend_from_slice(b"PAYLOAD");
            let (h, used) = parse(&with_payload).unwrap();
            assert_eq!(used, bytes.len(), "n={n}");
            assert_eq!(h.stanzas, st);
            assert_eq!(h.mac, mac);
            verify_mac(&fk, &h).unwrap();
            assert!(verify_mac(&[8u8; 32], &h).is_err());
        }
    }

    #[test]
    fn body_multiple_of_64_chars_has_empty_final_line() {
        // 48 bytes -> exactly 64 chars -> needs an empty trailing line.
        let st = vec![stanza(&["t"], vec![0u8; 48])];
        let prefix = String::from_utf8(marshal_prefix(&st).unwrap()).unwrap();
        let lines: Vec<&str> = prefix.split('\n').collect();
        assert_eq!(lines[2].len(), 64);
        assert_eq!(lines[3], "");
        assert_eq!(lines[4], "---");
    }

    fn good() -> Vec<u8> {
        marshal(&[stanza(&["t", "a"], vec![1, 2, 3])], &[0u8; 32])
            .unwrap()
            .0
    }

    #[test]
    fn rejects_bad_headers() {
        let g = good();
        assert!(parse(&g).is_ok());
        // wrong version
        let mut b = g.clone();
        b[8] = b'2';
        assert!(parse(&b).is_err());
        assert!(parse(b"secreto/v1").is_err());
        assert!(parse(b"").is_err());
        // truncated
        for cut in 1..g.len() {
            assert!(parse(&g[..cut]).is_err(), "cut {cut}");
        }
        // no stanza
        let none = format!("secreto/v1\n--- {}\n", "A".repeat(86));
        assert!(parse(none.as_bytes()).is_err());
        // double space in args
        let s = String::from_utf8(g.clone())
            .unwrap()
            .replace("-> t a", "-> t  a");
        assert!(parse(s.as_bytes()).is_err());
        // non-canonical body base64 ("AB" has trailing bits)
        let s = String::from_utf8(g.clone()).unwrap().replace("AQID", "AB");
        assert!(parse(s.as_bytes()).is_err());
        // padding in body
        let s = String::from_utf8(g.clone())
            .unwrap()
            .replace("AQID", "AQI=");
        assert!(parse(s.as_bytes()).is_err());
        // CRLF
        let s = String::from_utf8(g.clone()).unwrap().replace('\n', "\r\n");
        assert!(parse(s.as_bytes()).is_err());
        // non-canonical MAC (last char with nonzero trailing bits)
        let mut b = g.clone();
        let n = b.len();
        b[n - 2] = b'B';
        assert!(parse(&b).is_err());
        // MAC with padding / wrong length
        let bad = format!("secreto/v1\n-> t\n\n--- {}=\n", "A".repeat(86));
        assert!(parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn rejects_long_line_and_too_many_stanzas() {
        let long = format!("secreto/v1\n-> {}\n\n", "a".repeat(5000));
        assert!(parse(long.as_bytes()).is_err());
        let one = |i: usize| format!("-> t{}\n\n", i);
        let mut s = String::from("secreto/v1\n");
        for i in 0..=MAX_STANZAS {
            s.push_str(&one(i));
        }
        s.push_str(&format!("--- {}\n", "A".repeat(86)));
        assert!(parse(s.as_bytes()).is_err());
        let st: Vec<Stanza> = (0..=MAX_STANZAS)
            .map(|i| stanza(&["z"], vec![i as u8]))
            .collect();
        assert!(marshal_prefix(&st).is_err());
    }

    #[test]
    fn rejects_oversize_header() {
        let mut s = String::from("secreto/v1\n");
        // Each stanza ~ 4000 bytes of body lines; exceed 1 MiB with few stanzas
        // is impossible under the 256 stanza limit and 4096 line length unless
        // bodies are long: use a long body.
        s.push_str("-> t\n");
        let line = "A".repeat(64);
        for _ in 0..(MAX_HEADER_SIZE / 65 + 10) {
            s.push_str(&line);
            s.push('\n');
        }
        s.push('\n');
        s.push_str(&format!("--- {}\n", "A".repeat(86)));
        assert!(parse(s.as_bytes()).is_err());
    }

    #[test]
    fn argon2id_must_be_alone() {
        let fk = [0u8; 32];
        let st = vec![
            stanza(&["argon2id", "x"], vec![]),
            stanza(&["other"], vec![]),
        ];
        let (b, _) = marshal(&st, &fk).unwrap();
        assert!(parse(&b).is_err());
        let st = vec![
            stanza(&["argon2id", "x"], vec![]),
            stanza(&["argon2id", "x"], vec![]),
        ];
        let (b, _) = marshal(&st, &fk).unwrap();
        assert!(parse(&b).is_err());
        let st = vec![stanza(&["argon2id", "x"], vec![])];
        let (b, _) = marshal(&st, &fk).unwrap();
        assert!(parse(&b).is_ok());
    }

    #[test]
    fn mac_covers_through_hyphens() {
        let fk = [3u8; 32];
        let (b, mac) = marshal(&[stanza(&["t"], vec![9])], &fk).unwrap();
        let (h, _) = parse(&b).unwrap();
        assert!(h.mac_input.ends_with(b"\n---"));
        assert_eq!(compute_mac(&fk, &h.mac_input), mac);
        // tamper with a stanza -> MAC fails
        let mut t = b.clone();
        t[b"secreto/v1\n-> t\n".len()] ^= 1; // body char
        if let Ok((h2, _)) = parse(&t) {
            assert!(verify_mac(&fk, &h2).is_err());
        }
    }
}
