//! Encryption (`spec/format.md`).

use crate::argon;
use crate::armor;
use crate::error::{Error, Result};
use crate::header::{self, Stanza, MAX_STANZAS, TYPE_MLKEM};
use crate::hpke;
use crate::inner;
use crate::keys::Recipient;
use crate::sign::{signature_message, SigningKey};
use crate::stream;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use zeroize::Zeroizing;

/// Who to encrypt to.
#[derive(Debug)]
pub enum Recipients<'a> {
    /// One stanza per MLKEM1024-P384 recipient.
    Keys(&'a [Recipient]),
    /// A single Argon2id passphrase stanza (mutually exclusive with keys).
    Passphrase(&'a [u8]),
}

/// Encryption options.
#[derive(Debug, Default)]
pub struct EncryptOptions<'a> {
    /// Apply Padmé length padding.
    pub pad: bool,
    /// Sign the content with this key.
    pub signer: Option<&'a SigningKey>,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Io("random number generator failure".into()))?;
    Ok(b)
}

/// Build the `mlkem1024p384` stanza wrapping `file_key` for `recipient`.
pub fn mlkem_stanza(recipient: &Recipient, file_key: &[u8; 32]) -> Result<Stanza> {
    let (enc, body) = hpke::seal_base(recipient.as_bytes(), hpke::INFO, b"", file_key)?;
    debug_assert_eq!(body.len(), 48);
    Ok(Stanza {
        args: vec![TYPE_MLKEM.to_string(), STANDARD_NO_PAD.encode(&enc)],
        body,
    })
}

/// Encrypt `content` for `recipients`. Returns the binary `.sec` file.
pub fn encrypt(
    content: &[u8],
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<Vec<u8>> {
    let file_key = Zeroizing::new(random::<32>()?);
    let stanzas = match recipients {
        Recipients::Keys(keys) => {
            if keys.is_empty() {
                return Err(Error::InvalidKey("no recipients"));
            }
            if keys.len() > MAX_STANZAS {
                return Err(Error::InvalidKey("too many recipients"));
            }
            keys.iter()
                .map(|r| mlkem_stanza(r, &file_key))
                .collect::<Result<Vec<_>>>()?
        }
        Recipients::Passphrase(pw) => vec![argon::wrap(pw, &file_key)?],
    };
    encrypt_with_stanzas(&file_key, &stanzas, content, opts)
}

/// Encrypt `content` for `recipients` and ASCII-armor the result.
pub fn encrypt_armored(
    content: &[u8],
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<String> {
    Ok(armor::encode(&encrypt(content, recipients, opts)?))
}

/// Lower-level building block: assemble a file from an already-wrapped file
/// key. `stanzas` must wrap `file_key`.
pub fn encrypt_with_stanzas(
    file_key: &[u8; 32],
    stanzas: &[Stanza],
    content: &[u8],
    opts: &EncryptOptions<'_>,
) -> Result<Vec<u8>> {
    let (mut out, mac) = header::marshal(stanzas, file_key)?;

    let sigblock = match opts.signer {
        Some(sk) => Some(sk.sign(&signature_message(&mac, content))?),
        None => None,
    };
    let inner = inner::build(content, sigblock.as_ref(), opts.pad);

    let nonce = random::<{ stream::NONCE_LEN }>()?;
    let payload = stream::encrypt(file_key, &nonce, &inner)?;
    out.extend_from_slice(&payload);
    Ok(out)
}
