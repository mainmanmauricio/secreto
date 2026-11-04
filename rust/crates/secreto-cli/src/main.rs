// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! `secreto` — encrypt and decrypt files (`spec/cli.md`).

use clap::error::ErrorKind;
use clap::Parser;
use secreto_cli::{
    die, is_std, lower_hex, open_input, read_passphrase, read_secret_key_file, read_text_file,
    warn, with_output, CliError, Result, MAX_STDOUT_BUFFER,
};
use secreto_core::argon::ArgonParams;
use secreto_core::keys::{parse_identities, parse_recipients, parse_signing_key};
use secreto_core::{
    decrypt_to, encrypt_armored_to, encrypt_to, DecryptOptions, EncryptOptions, Recipient,
    Recipients, SignerPublicKey,
};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

const PROG: &str = "secreto";

/// Encrypt and decrypt files in the secreto/v1 format.
#[derive(Parser, Debug)]
#[command(name = "secreto", version, about, override_usage = USAGE)]
struct Args {
    /// Encrypt
    #[arg(short = 'e')]
    encrypt: bool,
    /// Decrypt
    #[arg(short = 'd')]
    decrypt: bool,
    /// Encrypt to Bech32 recipient (repeatable)
    #[arg(short = 'r', value_name = "RECIPIENT")]
    recipients: Vec<String>,
    /// Read recipients from file (one per line; `#` comments)
    #[arg(short = 'R', value_name = "FILE")]
    recipient_files: Vec<PathBuf>,
    /// Decrypt with identity file (repeatable)
    #[arg(short = 'i', value_name = "FILE")]
    identities: Vec<PathBuf>,
    /// Passphrase mode
    #[arg(short = 'p')]
    passphrase: bool,
    /// Argon2id memory cost in MiB (encrypt + `-p` only; default 64; range 64–4096)
    #[arg(long, value_name = "MIB")]
    memory: Option<u32>,
    /// ASCII armor output (encrypt only)
    #[arg(short = 'a')]
    armor: bool,
    /// Output path (default: stdout)
    #[arg(short = 'o', value_name = "OUT")]
    output: Option<String>,
    /// Apply Padmé length padding (encrypt only)
    #[arg(long)]
    pad: bool,
    /// Sign with signing secret key file
    #[arg(long, value_name = "KEYFILE")]
    sign: Option<PathBuf>,
    /// Require and verify a signature from this `secretosig` public key
    #[arg(long, value_name = "SIGNER_PUB")]
    verify: Option<String>,
    /// Input file (default: stdin; `-` is stdin)
    #[arg(value_name = "IN")]
    input: Option<String>,
}

const USAGE: &str =
    "secreto [-e] (-r RECIPIENT | -R FILE)... [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n       \
secreto [-e] -p [--memory MIB] [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n       \
secreto -d (-i FILE)... | -p [--verify SIGNER_PUB] [-o OUT] [IN]";

/// Resolve `--memory MIB` into ArgonParams. Exit 1 on misuse.
fn argon_params_from_args(a: &Args) -> Result<ArgonParams> {
    match a.memory {
        None => Ok(ArgonParams::DEFAULT),
        Some(_) if !a.passphrase => Err(CliError::usage("--memory requires -p")),
        Some(mib) if !(64..=4096).contains(&mib) => Err(CliError::usage(
            "--memory must be an integer between 64 and 4096 (MiB)",
        )),
        Some(mib) => Ok(ArgonParams {
            m_kib: mib.saturating_mul(1024),
            t: ArgonParams::DEFAULT.t,
            p: ArgonParams::DEFAULT.p,
        }),
    }
}

#[derive(PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn determine_mode(a: &Args) -> Result<Mode> {
    let has_rcpt = !a.recipients.is_empty() || !a.recipient_files.is_empty();
    match (a.encrypt, a.decrypt) {
        (true, true) => Err(CliError::usage("-e and -d are mutually exclusive")),
        (true, false) => Ok(Mode::Encrypt),
        (false, true) => Ok(Mode::Decrypt),
        (false, false) if has_rcpt || a.passphrase => {
            if !a.identities.is_empty() {
                Err(CliError::usage("-i requires -d"))
            } else {
                Ok(Mode::Encrypt)
            }
        }
        (false, false) => Err(CliError::usage(
            "specify -e or -d (or recipients / -p to imply -e)",
        )),
    }
}

fn load_recipients(a: &Args) -> Result<Vec<Recipient>> {
    let mut out = Vec::new();
    for r in &a.recipients {
        out.push(Recipient::from_bech32(r.trim()).map_err(|e| CliError::from(e).context("-r"))?);
    }
    for f in &a.recipient_files {
        let text = read_text_file(f)?;
        let v = parse_recipients(&text)
            .map_err(|e| CliError::from(e).context(f.display().to_string()))?;
        out.extend(v);
    }
    Ok(out)
}

fn run_encrypt(a: &Args) -> Result<()> {
    if !a.identities.is_empty() {
        return Err(CliError::usage("-i is only valid with -d"));
    }
    if a.verify.is_some() {
        return Err(CliError::usage("--verify is only valid with -d"));
    }
    let has_rcpt = !a.recipients.is_empty() || !a.recipient_files.is_empty();
    if a.passphrase && has_rcpt {
        return Err(CliError::usage("-p cannot be combined with -r/-R"));
    }
    if !a.passphrase && !has_rcpt {
        return Err(CliError::usage(
            "encryption requires at least one -r/-R recipient or -p",
        ));
    }

    // Refuse binary ciphertext to a terminal up front, before prompting.
    if !a.armor && is_std(a.output.as_deref()) && std::io::stdout().is_terminal() {
        return Err(CliError::usage(
            "refusing to write binary ciphertext to a terminal; use -a or -o",
        ));
    }

    let keys = if has_rcpt {
        load_recipients(a)?
    } else {
        Vec::new()
    };
    let signer = match &a.sign {
        Some(p) => {
            let text = read_secret_key_file(PROG, p)?;
            Some(
                parse_signing_key(&text)
                    .map_err(|e| CliError::from(e).context(p.display().to_string()))?,
            )
        }
        None => None,
    };
    let argon = argon_params_from_args(a)?;
    let pw = if a.passphrase {
        let pw = read_passphrase(true)?;
        if pw.is_empty() {
            return Err(CliError::usage("empty passphrase"));
        }
        Some(pw)
    } else {
        None
    };

    let opts = EncryptOptions {
        pad: a.pad,
        signer: signer.as_ref(),
        argon,
    };
    let mut input = open_input(a.input.as_deref())?;
    with_output(a.output.as_deref(), |out| {
        let recipients = match &pw {
            Some(pw) => Recipients::Passphrase(pw),
            None => Recipients::Keys(&keys),
        };
        if a.armor {
            encrypt_armored_to(&mut *input, out, recipients, &opts)?;
        } else {
            encrypt_to(&mut *input, out, recipients, &opts)?;
        }
        Ok(())
    })
}

fn load_verify_key(arg: &str) -> Result<SignerPublicKey> {
    let text;
    let s = if arg.starts_with("secretosig1") {
        arg.trim()
    } else if Path::new(arg).is_file() {
        text = read_text_file(Path::new(arg))?;
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let first = lines
            .next()
            .ok_or_else(|| CliError::usage(format!("{arg}: no signer public key found")))?;
        if lines.next().is_some() {
            return Err(CliError::usage(format!("{arg}: multiple keys in file")));
        }
        first
    } else {
        arg.trim()
    };
    SignerPublicKey::from_bech32(s).map_err(|e| CliError::from(e).context("--verify"))
}

fn run_decrypt(a: &Args) -> Result<()> {
    if !a.recipients.is_empty() || !a.recipient_files.is_empty() {
        return Err(CliError::usage("-r/-R are only valid when encrypting"));
    }
    if a.armor || a.pad || a.sign.is_some() || a.memory.is_some() {
        return Err(CliError::usage(
            "-a, --pad, --sign and --memory are only valid when encrypting",
        ));
    }
    if a.passphrase && !a.identities.is_empty() {
        return Err(CliError::usage("-p cannot be combined with -i"));
    }
    if !a.passphrase && a.identities.is_empty() {
        return Err(CliError::usage(
            "decryption requires at least one -i FILE or -p",
        ));
    }

    let mut ids = Vec::new();
    for f in &a.identities {
        let text = read_secret_key_file(PROG, f)?;
        let v = parse_identities(&text)
            .map_err(|e| CliError::from(e).context(f.display().to_string()))?;
        ids.extend(v);
    }
    let verify = a.verify.as_deref().map(load_verify_key).transpose()?;
    let pw = if a.passphrase {
        Some(read_passphrase(false)?)
    } else {
        None
    };

    let opts = DecryptOptions {
        identities: &ids,
        passphrase: pw.as_ref().map(|p| p.as_slice()),
        verify: verify.as_ref(),
    };
    let mut input = open_input(a.input.as_deref())?;

    // With --verify to stdout, buffer so we can enforce the 256 MiB cap and
    // avoid releasing content on failure. decrypt_to already verifies before
    // writing; the buffer is only for the size check.
    if is_std(a.output.as_deref()) && verify.is_some() {
        let mut buf = Vec::new();
        let meta = decrypt_to(&mut *input, &mut buf, &opts)?;
        if buf.len() > MAX_STDOUT_BUFFER {
            return Err(CliError::usage(
                "verified content exceeds 256 MiB; use -o to write to a file",
            ));
        }
        if let (Some(id), false) = (meta.signer_id, meta.verified) {
            warn(
                PROG,
                &format!(
                    "file is signed by signer_id {}; signature NOT verified (use --verify)",
                    lower_hex(&id)
                ),
            );
        }
        with_output(None, |out| {
            out.write_all(&buf)
                .map_err(|e| CliError::io(format!("writing stdout: {e}")))
        })
    } else {
        let mut meta_slot = None;
        with_output(a.output.as_deref(), |out| {
            let meta = decrypt_to(&mut *input, out, &opts)?;
            meta_slot = Some(meta);
            Ok(())
        })?;
        if let Some(meta) = meta_slot {
            if let (Some(id), false) = (meta.signer_id, meta.verified) {
                warn(
                    PROG,
                    &format!(
                        "file is signed by signer_id {}; signature NOT verified (use --verify)",
                        lower_hex(&id)
                    ),
                );
            }
        }
        Ok(())
    }
}

fn run() -> Result<()> {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = e.print();
                std::process::exit(0);
            }
            let rendered = e.to_string();
            let line = rendered
                .lines()
                .next()
                .unwrap_or("invalid arguments")
                .trim_start_matches("error: ");
            return Err(CliError::usage(line));
        }
    };
    match determine_mode(&args)? {
        Mode::Encrypt => run_encrypt(&args),
        Mode::Decrypt => run_decrypt(&args),
    }
}

fn main() {
    if let Err(e) = run() {
        die(PROG, &e);
    }
}
