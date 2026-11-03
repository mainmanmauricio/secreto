//! Decryption (`spec/format.md`, *Decryption order of checks*).

use crate::argon;
use crate::armor;
use crate::error::{Error, Result};
use crate::header::{self, Header, Stanza, TYPE_ARGON2ID, TYPE_MLKEM};
use crate::hpke;
use crate::inner;
use crate::kem;
use crate::keys::Identity;
use crate::sign::{signature_message, SignerPublicKey, SIGNER_ID_LEN};
use crate::stream;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use zeroize::Zeroizing;

/// Decryption inputs.
#[derive(Debug, Default)]
pub struct DecryptOptions<'a> {
    /// Identities to try against `mlkem1024p384` stanzas.
    pub identities: &'a [Identity],
    /// Passphrase to try against an `argon2id` stanza.
    pub passphrase: Option<&'a [u8]>,
    /// Require and verify a signature from this signer.
    pub verify: Option<&'a SignerPublicKey>,
}

/// Result of a successful decryption.
#[derive(Debug)]
pub struct Decrypted {
    /// The plaintext content.
    pub content: Zeroizing<Vec<u8>>,
    /// Signer id if the file is signed (callers SHOULD warn when this is
    /// `Some` and `verified` is `false`).
    pub signer_id: Option<[u8; SIGNER_ID_LEN]>,
    /// Whether a signature was verified against `DecryptOptions::verify`.
    pub verified: bool,
}

/// Try to parse an `mlkem1024p384` stanza into `(enc, body)`; `None` means
/// "treat as non-match".
fn parse_mlkem_stanza(s: &Stanza) -> Option<Vec<u8>> {
    if s.args.len() != 2 || s.body.len() != 48 {
        return None;
    }
    let enc = STANDARD_NO_PAD.decode(&s.args[1]).ok()?;
    (enc.len() == kem::CT_LEN).then_some(enc)
}

fn unwrap_file_key(header: &Header, opts: &DecryptOptions<'_>) -> Result<Zeroizing<[u8; 32]>> {
    for stanza in &header.stanzas {
        match stanza.kind() {
            TYPE_MLKEM => {
                if opts.identities.is_empty() {
                    continue;
                }
                let Some(enc) = parse_mlkem_stanza(stanza) else {
                    continue;
                };
                for id in opts.identities {
                    if let Ok(pt) = hpke::open_base(&enc, id.seed(), hpke::INFO, b"", &stanza.body)
                    {
                        if pt.len() == 32 {
                            let mut fk = Zeroizing::new([0u8; 32]);
                            fk.copy_from_slice(&pt);
                            return Ok(fk);
                        }
                    }
                }
            }
            TYPE_ARGON2ID => {
                // Parameters and lengths are validated even without a
                // passphrase so that malformed headers fail uniformly.
                argon::parse_stanza(stanza)?;
                if let Some(pw) = opts.passphrase {
                    match argon::unwrap(stanza, pw) {
                        Ok(fk) => return Ok(fk),
                        Err(Error::NoMatch) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            _ => {} // unrecognized types are ignored
        }
    }
    Err(Error::NoMatch)
}

/// Decrypt a `.sec` file (binary or ASCII-armored).
pub fn decrypt(data: &[u8], opts: &DecryptOptions<'_>) -> Result<Decrypted> {
    // 1. armor
    let decoded;
    let data = if armor::is_armored(data) {
        decoded = armor::decode(data)?;
        &decoded[..]
    } else {
        data
    };

    // 2. header
    let (hdr, hdr_len) = header::parse(data)?;

    // 3-4. file key
    let file_key = unwrap_file_key(&hdr, opts)?;

    // 5. header MAC
    header::verify_mac(&file_key, &hdr)?;

    // 6. payload
    let plaintext = stream::decrypt(&file_key, &data[hdr_len..])?;

    // 7. inner plaintext
    let parsed = inner::parse(plaintext)?;

    // 8-9. signatures
    let signer_id = parsed.sigblock.as_ref().map(|s| s.signer_id);
    let mut verified = false;
    if let Some(pk) = opts.verify {
        let sig = parsed
            .sigblock
            .as_ref()
            .ok_or(Error::Signature("file is not signed"))?;
        let msg = signature_message(&hdr.mac, &parsed.content);
        pk.verify(sig, &msg)?;
        verified = true;
    }

    Ok(Decrypted {
        content: parsed.content,
        signer_id,
        verified,
    })
}
