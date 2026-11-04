// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Decryption (`spec/format.md`, *Decryption order of checks*).

use crate::argon;
use crate::armor;
use crate::error::{Error, Result};
use crate::header::{self, Header, Stanza, MAX_HEADER_SIZE, TYPE_ARGON2ID, TYPE_MLKEM};
use crate::hpke;
use crate::inner;
use crate::kem;
use crate::keys::Identity;
use crate::sign::{
    signature_message, signature_message_hashed, SigBlock, SignerPublicKey, SIGNER_ID_LEN,
    SIGBLOCK_LEN,
};
use crate::stream::{self, StreamDecryptor, CHUNK_SIZE, NONCE_LEN, TAG_LEN};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use sha2::{Digest, Sha512};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

/// Metadata returned by streaming decrypt (content is written to the sink).
#[derive(Debug)]
pub struct DecryptMeta {
    /// Signer id if the file is signed.
    pub signer_id: Option<[u8; SIGNER_ID_LEN]>,
    /// Whether a signature was verified against `DecryptOptions::verify`.
    pub verified: bool,
    /// Byte length of the released content.
    pub content_len: u64,
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

struct Spill {
    file: File,
    path: PathBuf,
}

impl Drop for Spill {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn make_spill() -> Result<Spill> {
    let dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    for attempt in 0..64u32 {
        let path = dir.join(format!(
            "secreto-spill.{}.{nanos:08x}.{attempt}",
            std::process::id()
        ));
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        match opts.open(&path) {
            Ok(file) => {
                return Ok(Spill { file, path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
    Err(Error::Io("could not create spill file".into()))
}

fn read_exact_from(r: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            return Err(Error::Format("payload authentication failed"));
        }
        got += n;
    }
    Ok(())
}

/// Decrypt STREAM ciphertext from `payload` into `spill`.
fn decrypt_stream_to_spill(
    file_key: &[u8; 32],
    payload: &mut dyn Read,
    spill: &mut File,
) -> Result<()> {
    let mut nonce = [0u8; NONCE_LEN];
    read_exact_from(payload, &mut nonce)?;
    let key = stream::payload_key(file_key, &nonce);
    let mut dec = StreamDecryptor::new(&key);
    let full = CHUNK_SIZE + TAG_LEN;
    let mut leftover = Vec::with_capacity(full + 8192);
    let mut tmp = [0u8; 8192];
    let mut saw_body = false;
    loop {
        while leftover.len() < full {
            let n = payload.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            leftover.extend_from_slice(&tmp[..n]);
        }
        if leftover.len() < full {
            if leftover.is_empty() {
                if !saw_body {
                    return Err(Error::Format("payload authentication failed"));
                }
                break;
            }
            let pt = dec.decrypt_chunk(&leftover, true)?;
            spill.write_all(&pt)?;
            saw_body = true;
            break;
        }
        // At least one full ciphertext chunk is buffered.
        if leftover.len() == full {
            let mut peek = [0u8; 1];
            let n = payload.read(&mut peek)?;
            if n == 0 {
                let pt = dec.decrypt_chunk(&leftover, true)?;
                spill.write_all(&pt)?;
                saw_body = true;
                break;
            }
            let pt = dec.decrypt_chunk(&leftover[..full], false)?;
            spill.write_all(&pt)?;
            saw_body = true;
            leftover.clear();
            leftover.push(peek[0]);
            continue;
        }
        let pt = dec.decrypt_chunk(&leftover[..full], false)?;
        spill.write_all(&pt)?;
        saw_body = true;
        leftover.drain(..full);
    }
    if !saw_body {
        return Err(Error::Format("payload authentication failed"));
    }
    spill.flush()?;
    Ok(())
}

fn release_from_spill(
    spill: &mut File,
    hdr_mac: &[u8; 64],
    opts: &DecryptOptions<'_>,
    writer: &mut dyn Write,
) -> Result<DecryptMeta> {
    let len = spill.seek(SeekFrom::End(0))?;
    if len < 2 {
        return Err(Error::Format("inner plaintext too short"));
    }
    spill.seek(SeekFrom::Start(0))?;
    let mut flags = [0u8; 1];
    spill.read_exact(&mut flags)?;
    let signed = match flags[0] {
        inner::FLAG_UNSIGNED => false,
        inner::FLAG_SIGNED => true,
        _ => return Err(Error::Format("invalid inner flags")),
    };

    let sig_len = if signed { SIGBLOCK_LEN as u64 } else { 0 };
    if len < 1 + 1 + sig_len {
        return Err(Error::Format("truncated signature block"));
    }
    let body_end = len - sig_len;

    let mut sigblock = None;
    if signed {
        spill.seek(SeekFrom::Start(body_end))?;
        let mut sb = vec![0u8; SIGBLOCK_LEN];
        spill.read_exact(&mut sb)?;
        sigblock = Some(SigBlock::from_bytes(&sb)?);
    }

    // Find terminator: strip trailing zeros from [1, body_end), require 0x80.
    let mut pos = body_end;
    let mut scan_buf = [0u8; 4096];
    'outer: loop {
        let start = pos.saturating_sub(scan_buf.len() as u64).max(1);
        let n = (pos - start) as usize;
        spill.seek(SeekFrom::Start(start))?;
        spill.read_exact(&mut scan_buf[..n])?;
        for i in (0..n).rev() {
            if scan_buf[i] != 0 {
                pos = start + i as u64;
                break 'outer;
            }
        }
        pos = start;
        if pos <= 1 {
            return Err(Error::Format("invalid inner padding"));
        }
    }
    spill.seek(SeekFrom::Start(pos))?;
    let mut term = [0u8; 1];
    spill.read_exact(&mut term)?;
    if term[0] != inner::TERMINATOR {
        return Err(Error::Format("invalid inner padding"));
    }
    let content_end = pos;
    let content_len = content_end - 1;

    let signer_id = sigblock.as_ref().map(|s| s.signer_id);
    let mut verified = false;
    if let Some(pk) = opts.verify {
        let sig = sigblock
            .as_ref()
            .ok_or(Error::Signature("file is not signed"))?;
        spill.seek(SeekFrom::Start(1))?;
        let mut hasher = Sha512::new();
        let mut left = content_len;
        while left > 0 {
            let n = left.min(scan_buf.len() as u64) as usize;
            spill.read_exact(&mut scan_buf[..n])?;
            hasher.update(&scan_buf[..n]);
            left -= n as u64;
        }
        let hash: [u8; 64] = hasher.finalize().into();
        let msg = signature_message_hashed(hdr_mac, content_len, &hash);
        pk.verify(sig, &msg)?;
        verified = true;
    }

    spill.seek(SeekFrom::Start(1))?;
    let mut left = content_len;
    while left > 0 {
        let n = left.min(scan_buf.len() as u64) as usize;
        spill.read_exact(&mut scan_buf[..n])?;
        writer.write_all(&scan_buf[..n])?;
        left -= n as u64;
    }

    Ok(DecryptMeta {
        signer_id,
        verified,
        content_len,
    })
}

/// Read ciphertext from `reader`, writing content to `writer`.
///
/// STREAM plaintext is spilled to a temp file so Padmé padding and the
/// signature block can be stripped from the end. Argon2 runs after the
/// header is parsed and before the body is decrypted.
pub fn decrypt_to(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    opts: &DecryptOptions<'_>,
) -> Result<DecryptMeta> {
    // Accumulate until armor can be detected and (for binary) the header parses.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut armored: Option<bool> = None;

    loop {
        let n = reader.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if armored.is_none() && buf.len() >= 16 {
            // Skip leading whitespace for detection.
            armored = Some(armor::is_armored(&buf));
        }
        if armored == Some(false) {
            match header::parse(&buf) {
                Ok(_) => break,
                Err(Error::Format(msg))
                    if matches!(
                        msg,
                        "malformed header" | "header line too long" | "header too large"
                    ) && buf.len() < MAX_HEADER_SIZE =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        if armored == Some(true) {
            // Keep reading until EOF for armored input (decode needs the END line).
            continue;
        }
        if buf.len() > MAX_HEADER_SIZE && armored != Some(true) {
            return Err(Error::Format("header too large"));
        }
    }

    let armored = armored.unwrap_or_else(|| armor::is_armored(&buf));
    let decoded;
    let data: &[u8] = if armored {
        decoded = armor::decode(&buf)?;
        &decoded
    } else {
        &buf
    };

    let (hdr, hdr_len) = header::parse(data)?;
    let file_key = unwrap_file_key(&hdr, opts)?;
    header::verify_mac(&file_key, &hdr)?;

    let mut spill = make_spill()?;
    let mut payload_cursor = std::io::Cursor::new(&data[hdr_len..]);
    // For binary files we may still have unread payload on `reader` after `buf`.
    if armored {
        decrypt_stream_to_spill(&file_key, &mut payload_cursor, &mut spill.file)?;
    } else {
        let mut chained = payload_cursor.chain(reader);
        decrypt_stream_to_spill(&file_key, &mut chained, &mut spill.file)?;
    }

    release_from_spill(&mut spill.file, &hdr.mac, opts, writer)
}
