//! Inner plaintext: `flags || content || 0x80 || 0x00*k || [sigblock]`
//! (`spec/format.md`, *Inner plaintext*).

use crate::error::{Error, Result};
use crate::padme;
use crate::sign::{SigBlock, SIGBLOCK_LEN};
use zeroize::Zeroizing;

/// Flags value for an unsigned file.
pub const FLAG_UNSIGNED: u8 = 0x00;
/// Flags value for a signed file.
pub const FLAG_SIGNED: u8 = 0x01;
/// Terminator byte.
pub const TERMINATOR: u8 = 0x80;

/// Parsed inner plaintext.
pub struct Inner {
    /// The user content.
    pub content: Zeroizing<Vec<u8>>,
    /// The signature block, if the file is signed.
    pub sigblock: Option<SigBlock>,
}

impl core::fmt::Debug for Inner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Inner")
            .field("content_len", &self.content.len())
            .field("sigblock", &self.sigblock)
            .finish()
    }
}

/// Unpadded inner length `L` for the given content length.
pub fn unpadded_len(content_len: usize, signed: bool) -> u64 {
    1 + content_len as u64 + 1 + if signed { SIGBLOCK_LEN as u64 } else { 0 }
}

/// Build the inner plaintext. With `pad`, Padmé zeros are inserted after
/// the terminator and before the signature block.
pub fn build(content: &[u8], sigblock: Option<&SigBlock>, pad: bool) -> Zeroizing<Vec<u8>> {
    let signed = sigblock.is_some();
    let l = unpadded_len(content.len(), signed);
    let k = if pad {
        padme::padding_len(l) as usize
    } else {
        0
    };
    let mut v = Zeroizing::new(Vec::with_capacity(l as usize + k));
    v.push(if signed { FLAG_SIGNED } else { FLAG_UNSIGNED });
    v.extend_from_slice(content);
    v.push(TERMINATOR);
    let new_len = v.len() + k;
    v.resize(new_len, 0);
    if let Some(sig) = sigblock {
        v.extend_from_slice(&sig.to_bytes());
    }
    v
}

/// Parse the inner plaintext (consumes the decrypted STREAM plaintext).
pub fn parse(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Inner> {
    if plaintext.len() < 2 {
        return Err(Error::Format("inner plaintext too short"));
    }
    let signed = match plaintext[0] {
        FLAG_UNSIGNED => false,
        FLAG_SIGNED => true,
        _ => return Err(Error::Format("invalid inner flags")),
    };
    let mut sigblock = None;
    let mut end = plaintext.len();
    if signed {
        if end < 1 + 1 + SIGBLOCK_LEN {
            return Err(Error::Format("truncated signature block"));
        }
        end -= SIGBLOCK_LEN;
        sigblock = Some(SigBlock::from_bytes(&plaintext[end..])?);
    }
    // Strip trailing zeros, then require the terminator.
    let body = &plaintext[1..end];
    let zeros = body.iter().rev().take_while(|&&b| b == 0).count();
    let term = body.len().checked_sub(zeros + 1);
    match term {
        Some(i) if body[i] == TERMINATOR => {
            let content_end = 1 + i;
            plaintext.truncate(content_end);
            plaintext.drain(..1);
            Ok(Inner {
                content: plaintext,
                sigblock,
            })
        }
        _ => Err(Error::Format("invalid inner padding")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{SigningKey, SIGBLOCK_LEN};

    fn sig() -> SigBlock {
        SigBlock::from_bytes(&vec![0x33u8; SIGBLOCK_LEN]).unwrap()
    }

    #[test]
    fn unsigned_roundtrip() {
        for content in [
            &b""[..],
            b"a",
            b"hello",
            &[0x80u8],
            &[0u8, 0, 0],
            &[0x80, 0, 0x80, 0],
        ] {
            for pad in [false, true] {
                let inner = build(content, None, pad);
                if !pad {
                    assert_eq!(inner.len(), content.len() + 2);
                } else {
                    assert_eq!(inner.len() as u64, padme::padme(content.len() as u64 + 2));
                }
                assert_eq!(inner[0], 0);
                let p = parse(inner).unwrap();
                assert_eq!(&p.content[..], content);
                assert!(p.sigblock.is_none());
            }
        }
    }

    #[test]
    fn signed_roundtrip_and_padding_position() {
        let s = sig();
        for n in [0usize, 1, 100, 1000] {
            let content: Vec<u8> = (0..n).map(|i| (i % 255) as u8 + 1).collect();
            for pad in [false, true] {
                let inner = build(&content, Some(&s), pad);
                assert_eq!(inner[0], 1);
                // sigblock is always the final 4723 bytes
                assert_eq!(&inner[inner.len() - SIGBLOCK_LEN..], &s.to_bytes()[..]);
                let l = unpadded_len(n, true);
                let expect = if pad { padme::padme(l) } else { l };
                assert_eq!(inner.len() as u64, expect);
                // terminator sits right after the content
                assert_eq!(inner[1 + n], 0x80);
                let p = parse(inner).unwrap();
                assert_eq!(&p.content[..], &content[..]);
                assert_eq!(p.sigblock.unwrap(), s);
            }
        }
    }

    #[test]
    fn rejects_invalid() {
        let z = |v: Vec<u8>| Zeroizing::new(v);
        assert!(parse(z(vec![])).is_err());
        assert!(parse(z(vec![0])).is_err());
        assert!(parse(z(vec![0x80])).is_err());
        // bad flags
        assert!(parse(z(vec![2, 0x80])).is_err());
        assert!(parse(z(vec![0xff, 0x80])).is_err());
        // missing terminator
        assert!(parse(z(vec![0, 1, 2, 3])).is_err());
        assert!(parse(z(vec![0, 0, 0, 0])).is_err());
        assert!(parse(z(vec![0, 0x80, 0, 1])).is_err());
        assert!(parse(z(vec![0, 0])).is_err());
        // flags only + terminator is ok (empty content)
        assert_eq!(parse(z(vec![0, 0x80])).unwrap().content.len(), 0);
        // signed but truncated
        let mut v = vec![1u8, 0x80];
        v.extend_from_slice(&vec![0u8; SIGBLOCK_LEN - 1]);
        assert!(parse(z(v)).is_err());
        // signed with no terminator before sigblock
        let mut v = vec![1u8];
        v.extend_from_slice(&vec![0u8; SIGBLOCK_LEN + 1]);
        assert!(parse(z(v)).is_err());
        // signed: zeros between terminator and sigblock only
        let mut v = vec![1u8, 0x80, 0, 0];
        v.extend_from_slice(&vec![9u8; SIGBLOCK_LEN]);
        assert!(parse(z(v)).is_ok());
        // sigblock bytes are not mistaken for padding even if they end in 0x80
        let mut v = vec![1u8, b'x', 0x80];
        let mut sb = vec![0u8; SIGBLOCK_LEN];
        *sb.last_mut().unwrap() = 0x80;
        v.extend_from_slice(&sb);
        let p = parse(z(v)).unwrap();
        assert_eq!(&p.content[..], b"x");
    }

    #[test]
    fn works_with_real_signature_block() {
        let sk = SigningKey::from_bytes(&[1u8; 64]).unwrap();
        let sb = sk.sign(b"m").unwrap();
        let inner = build(b"data", Some(&sb), true);
        let p = parse(inner).unwrap();
        assert_eq!(p.sigblock.unwrap(), sb);
    }
}
