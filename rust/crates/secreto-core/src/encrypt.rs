// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Encryption (`spec/format.md`).

use crate::argon;
use crate::armor;
use crate::error::{Error, Result};
use crate::header::{self, Stanza, MAX_STANZAS, TYPE_MLKEM};
use crate::hpke;
use crate::inner;
use crate::keys::Recipient;
use crate::padme;
use crate::sign::{signature_message, signature_message_hashed, SigningKey};
use crate::stream::{self, StreamEncryptor, CHUNK_SIZE};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use sha2::{Digest, Sha512};
use std::io::{Read, Write};
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
#[derive(Debug)]
pub struct EncryptOptions<'a> {
    /// Apply Padmé length padding.
    pub pad: bool,
    /// Sign the content with this key.
    pub signer: Option<&'a SigningKey>,
    /// Argon2id parameters used when encrypting to a passphrase.
    pub argon: argon::ArgonParams,
}

impl Default for EncryptOptions<'_> {
    fn default() -> Self {
        Self {
            pad: false,
            signer: None,
            argon: argon::ArgonParams::DEFAULT,
        }
    }
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

fn build_stanzas(
    file_key: &[u8; 32],
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<Vec<Stanza>> {
    match recipients {
        Recipients::Keys(keys) => {
            if keys.is_empty() {
                return Err(Error::InvalidKey("no recipients"));
            }
            if keys.len() > MAX_STANZAS {
                return Err(Error::InvalidKey("too many recipients"));
            }
            keys.iter()
                .map(|r| mlkem_stanza(r, file_key))
                .collect::<Result<Vec<_>>>()
        }
        Recipients::Passphrase(pw) => {
            if !opts.argon.in_decrypt_range() {
                return Err(Error::InvalidKey("argon2id parameters out of range"));
            }
            Ok(vec![argon::wrap(pw, file_key, opts.argon)?])
        }
    }
}

/// Encrypt `content` for `recipients`. Returns the binary `.sec` file.
pub fn encrypt(
    content: &[u8],
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<Vec<u8>> {
    let file_key = Zeroizing::new(random::<32>()?);
    let stanzas = build_stanzas(&file_key, recipients, opts)?;
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

/// Flush full STREAM chunks from `buf`, leaving a partial chunk (or empty).
fn flush_full_chunks(
    enc: &mut StreamEncryptor,
    buf: &mut Vec<u8>,
    out: &mut dyn Write,
) -> Result<()> {
    while buf.len() >= CHUNK_SIZE {
        let ct = enc.encrypt_chunk(&buf[..CHUNK_SIZE], false)?;
        out.write_all(&ct)?;
        buf.drain(..CHUNK_SIZE);
    }
    Ok(())
}

/// Encrypt plaintext from `reader` into a binary `.sec` file on `writer`.
///
/// Peak memory is one STREAM chunk plus Argon2 (when using a passphrase).
/// The passphrase wrap runs before any content is read.
pub fn encrypt_to(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<()> {
    let file_key = Zeroizing::new(random::<32>()?);
    let stanzas = build_stanzas(&file_key, recipients, opts)?;
    let (hdr, mac) = header::marshal(&stanzas, &file_key)?;
    writer.write_all(&hdr)?;

    let nonce = random::<{ stream::NONCE_LEN }>()?;
    writer.write_all(&nonce)?;
    let key = stream::payload_key(&file_key, &nonce);
    let mut enc = StreamEncryptor::new(&key);

    let signed = opts.signer.is_some();
    let mut buf = Vec::with_capacity(CHUNK_SIZE);
    buf.push(if signed {
        inner::FLAG_SIGNED
    } else {
        inner::FLAG_UNSIGNED
    });

    let mut hasher = Sha512::new();
    let mut content_len: u64 = 0;
    let mut read_buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut read_buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&read_buf[..n]);
        content_len = content_len
            .checked_add(n as u64)
            .ok_or(Error::Format("content too large"))?;
        buf.extend_from_slice(&read_buf[..n]);
        flush_full_chunks(&mut enc, &mut buf, writer)?;
    }

    let sigblock = match opts.signer {
        Some(sk) => {
            let hash: [u8; 64] = hasher.finalize().into();
            let msg = signature_message_hashed(&mac, content_len, &hash);
            Some(sk.sign(&msg)?)
        }
        None => {
            let _ = hasher.finalize();
            None
        }
    };

    let l = inner::unpadded_len(content_len as usize, signed);
    let k = if opts.pad {
        padme::padding_len(l) as usize
    } else {
        0
    };
    buf.push(inner::TERMINATOR);
    buf.resize(buf.len() + k, 0);
    if let Some(sig) = &sigblock {
        buf.extend_from_slice(&sig.to_bytes());
    }

    // Leave a non-empty final chunk (1..=CHUNK_SIZE). When Padmé makes the
    // inner plaintext an exact multiple of CHUNK_SIZE, flushing with `>=`
    // would drain the buffer and wrongly reject an empty last chunk.
    while buf.len() > CHUNK_SIZE {
        let ct = enc.encrypt_chunk(&buf[..CHUNK_SIZE], false)?;
        writer.write_all(&ct)?;
        buf.drain(..CHUNK_SIZE);
    }
    if buf.is_empty() {
        return Err(Error::Format("empty STREAM plaintext"));
    }
    let ct = enc.encrypt_chunk(&buf, true)?;
    writer.write_all(&ct)?;
    Ok(())
}

/// Encrypt from `reader` and write ASCII-armored ciphertext to `writer`.
pub fn encrypt_armored_to(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    recipients: Recipients<'_>,
    opts: &EncryptOptions<'_>,
) -> Result<()> {
    let mut armor_out = armor::ArmorWriter::new(writer);
    encrypt_to(reader, &mut armor_out, recipients, opts)?;
    armor_out.finish()?;
    Ok(())
}
