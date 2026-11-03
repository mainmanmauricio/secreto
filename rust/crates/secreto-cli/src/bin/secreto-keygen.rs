//! `secreto-keygen` — generate and inspect secreto keys (`spec/cli.md`).

use clap::error::ErrorKind;
use clap::Parser;
use secreto_cli::{
    die, is_std, read_secret_key_input, write_new_secret_file, write_stdout, CliError, Result,
};
use secreto_core::keys::{parse_identities, parse_signing_key};
use secreto_core::{Identity, SigningKey};
use std::path::Path;
use zeroize::Zeroizing;

const PROG: &str = "secreto-keygen";

/// Generate secreto identities and signing keys.
#[derive(Parser, Debug)]
#[command(name = "secreto-keygen", version, about, override_usage = USAGE)]
struct Args {
    /// Generate / convert a signing key instead of an identity
    #[arg(long)]
    signing: bool,
    /// Read a secret key and print its public key to stdout
    #[arg(short = 'y')]
    convert: bool,
    /// Write the secret key to this path (mode 0600; must not exist)
    #[arg(short = 'o', value_name = "OUT")]
    output: Option<String>,
    /// Secret key file for -y (default: stdin)
    #[arg(value_name = "IN")]
    input: Option<String>,
}

const USAGE: &str = "secreto-keygen [-o OUT]\n       \
secreto-keygen -y [IN]\n       \
secreto-keygen --signing [-o OUT]\n       \
secreto-keygen --signing -y [IN]";

fn emit_secret(out: Option<&str>, secret: &str) -> Result<()> {
    let data = Zeroizing::new(format!("{secret}\n"));
    if is_std(out) {
        write_stdout(data.as_bytes())
    } else {
        write_new_secret_file(Path::new(out.expect("checked")), data.as_bytes())
    }
}

fn run() -> Result<()> {
    let a = match Args::try_parse() {
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

    if a.convert {
        if a.output.is_some() {
            return Err(CliError::usage("-o is not valid with -y"));
        }
        let text = read_secret_key_input(PROG, a.input.as_deref())?;
        let name = a.input.as_deref().filter(|p| *p != "-").unwrap_or("stdin");
        let mut out = String::new();
        if a.signing {
            let sk = parse_signing_key(&text).map_err(|e| CliError::from(e).context(name))?;
            out.push_str(&sk.public_key().to_bech32());
            out.push('\n');
        } else {
            for id in parse_identities(&text).map_err(|e| CliError::from(e).context(name))? {
                out.push_str(&id.recipient()?.to_bech32());
                out.push('\n');
            }
        }
        return write_stdout(out.as_bytes());
    }

    if a.input.is_some() {
        return Err(CliError::usage("IN is only valid with -y"));
    }
    if a.signing {
        let sk = SigningKey::generate()?;
        emit_secret(a.output.as_deref(), &sk.to_bech32())?;
        eprintln!("{}", sk.public_key().to_bech32());
    } else {
        let id = Identity::generate()?;
        emit_secret(a.output.as_deref(), &id.to_bech32())?;
        eprintln!("{}", id.recipient()?.to_bech32());
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        die(PROG, &e);
    }
}
