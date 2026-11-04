// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Strict PEM armor (RFC 7468 §3) with label `SECRETO ENCRYPTED FILE`.

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::Write;

/// PEM label.
pub const LABEL: &str = "SECRETO ENCRYPTED FILE";
const BEGIN: &str = "-----BEGIN SECRETO ENCRYPTED FILE-----";
const END: &str = "-----END SECRETO ENCRYPTED FILE-----";
const COLS: usize = 64;

/// Streaming PEM writer: buffers raw bytes, emits Base64 lines of 64 columns.
pub struct ArmorWriter<'a> {
    inner: &'a mut dyn Write,
    pending: Vec<u8>,
    started: bool,
    finished: bool,
}

impl<'a> ArmorWriter<'a> {
    /// Create a writer; the BEGIN line is emitted on the first write.
    pub fn new(inner: &'a mut dyn Write) -> Self {
        Self {
            inner,
            pending: Vec::with_capacity(COLS * 3 / 4 + 3),
            started: false,
            finished: false,
        }
    }

    fn emit_begin(&mut self) -> Result<()> {
        if !self.started {
            self.inner.write_all(BEGIN.as_bytes())?;
            self.inner.write_all(b"\n")?;
            self.started = true;
        }
        Ok(())
    }

    fn flush_full_lines(&mut self) -> Result<()> {
        // Every 3 raw bytes become 4 Base64 chars; emit 16 groups (= 64 chars).
        while self.pending.len() >= 48 {
            let chunk = &self.pending[..48];
            let line = STANDARD.encode(chunk);
            debug_assert_eq!(line.len(), COLS);
            self.inner.write_all(line.as_bytes())?;
            self.inner.write_all(b"\n")?;
            self.pending.drain(..48);
        }
        Ok(())
    }

    /// Write the END line and any remaining Base64. Must be called once.
    pub fn finish(mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.emit_begin()?;
        if !self.pending.is_empty() {
            let line = STANDARD.encode(&self.pending);
            self.inner.write_all(line.as_bytes())?;
            self.inner.write_all(b"\n")?;
            self.pending.clear();
        } else if !self.started {
            // empty body is invalid for our format, but finish still closes.
        }
        self.inner.write_all(END.as_bytes())?;
        self.inner.write_all(b"\n")?;
        self.finished = true;
        Ok(())
    }
}

impl Write for ArmorWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.finished {
            return Err(std::io::Error::other("armor writer already finished"));
        }
        self.emit_begin()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pending.extend_from_slice(buf);
        self.flush_full_lines()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Encode `data` as a PEM block (LF line endings, trailing LF).
pub fn encode(data: &[u8]) -> String {
    let b64 = STANDARD.encode(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / COLS + BEGIN.len() + END.len() + 4);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(COLS) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Does `data` look like armored input (after optional leading whitespace)?
pub fn is_armored(data: &[u8]) -> bool {
    let start = data.iter().position(|b| !is_ws(*b)).unwrap_or(data.len());
    data[start..].starts_with(b"-----BEGIN")
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Strictly decode a PEM block.
///
/// Only surrounding whitespace is tolerated. Lines may end in LF or CRLF.
/// All body lines must be exactly 64 characters, except the last which must
/// be 1..=64 characters. Base64 must be canonical (padding required, zero
/// trailing bits).
pub fn decode(data: &[u8]) -> Result<Vec<u8>> {
    const ERR: &str = "invalid armor";
    let text = std::str::from_utf8(data).map_err(|_| Error::Format(ERR))?;
    let text = text.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));

    if lines.next() != Some(BEGIN) {
        return Err(Error::Format(ERR));
    }
    let mut body: Vec<&str> = Vec::new();
    let mut ended = false;
    for l in lines.by_ref() {
        if l == END {
            ended = true;
            break;
        }
        body.push(l);
    }
    // Nothing may follow the END line (surrounding whitespace was trimmed).
    if !ended || lines.next().is_some() || body.is_empty() {
        return Err(Error::Format(ERR));
    }
    let (last, full) = body.split_last().expect("non-empty");
    if full.iter().any(|l| l.len() != COLS) || last.is_empty() || last.len() > COLS {
        return Err(Error::Format(ERR));
    }
    let joined: String = body.concat();
    let decoded = STANDARD
        .decode(joined.as_bytes())
        .map_err(|_| Error::Format(ERR))?;
    if decoded.is_empty() {
        return Err(Error::Format(ERR));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sizes() {
        for n in [1usize, 2, 3, 47, 48, 49, 95, 96, 97, 1000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 31) as u8).collect();
            let a = encode(&data);
            assert!(a.starts_with(BEGIN));
            assert!(a.ends_with(&format!("{END}\n")));
            assert!(a.lines().all(|l| l.len() <= 64 || l == BEGIN || l == END));
            assert_eq!(decode(a.as_bytes()).unwrap(), data, "n={n}");
            assert!(is_armored(a.as_bytes()));
        }
    }

    #[test]
    fn accepts_crlf_and_surrounding_ws() {
        let data = vec![7u8; 100];
        let a = encode(&data);
        let crlf = a.replace('\n', "\r\n");
        assert_eq!(decode(crlf.as_bytes()).unwrap(), data);
        let padded = format!("\n\n  {a}\n\n");
        assert_eq!(decode(padded.as_bytes()).unwrap(), data);
    }

    #[test]
    fn rejects_non_canonical() {
        let data = vec![7u8; 100];
        let a = encode(&data);
        // junk before / after
        assert!(decode(format!("x{a}").as_bytes()).is_err());
        assert!(decode(format!("{a}x").as_bytes()).is_err());
        assert!(decode(format!("{a}{a}").as_bytes()).is_err());
        // wrong label
        assert!(decode(a.replace("SECRETO", "OTHER").as_bytes()).is_err());
        // missing end
        assert!(decode(a.replace(END, "").as_bytes()).is_err());
        // empty body
        assert!(decode(format!("{BEGIN}\n{END}\n").as_bytes()).is_err());
        // short non-final line
        let lines: Vec<&str> = a.lines().collect();
        let mut bad = lines.clone();
        bad[1] = &bad[1][..63];
        assert!(decode((bad.join("\n") + "\n").as_bytes()).is_err());
        // empty final line
        let bad = format!("{}\n\n{END}\n", lines[..lines.len() - 1].join("\n"));
        assert!(decode(bad.as_bytes()).is_err());
        // non-canonical trailing bits: "AB==" decodes with nonzero trailing bits
        let bad = format!("{BEGIN}\nAB==\n{END}\n");
        assert!(decode(bad.as_bytes()).is_err());
        // missing padding
        let bad = format!("{BEGIN}\nAA\n{END}\n");
        assert!(decode(bad.as_bytes()).is_err());
        // whitespace inside a body line
        let bad = format!("{BEGIN}\nAA A\n{END}\n");
        assert!(decode(bad.as_bytes()).is_err());
    }

    #[test]
    fn detects_armor() {
        assert!(!is_armored(b"secreto/v1\n"));
        assert!(is_armored(b"\n -----BEGIN SECRETO ENCRYPTED FILE-----"));
    }
}
