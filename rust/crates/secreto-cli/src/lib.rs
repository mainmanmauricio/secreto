// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! Shared helpers for the `secreto` and `secreto-keygen` binaries
//! (`spec/cli.md`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Environment variable naming the passphrase file descriptor.
pub const ENV_PASSPHRASE_FD: &str = "SECRETO_PASSPHRASE_FD";
/// Maximum plaintext buffered in memory for stdout output with `--verify`.
pub const MAX_STDOUT_BUFFER: usize = 256 * 1024 * 1024;
/// Maximum accepted passphrase length when read from a file descriptor.
const MAX_PASSPHRASE_LEN: u64 = 1 << 20;

/// An error carrying a normative exit code.
#[derive(Debug)]
pub struct CliError {
    /// Process exit code (1-5).
    pub code: i32,
    /// One-line message; never contains secrets.
    pub msg: String,
}

impl CliError {
    /// Usage error or invalid key file (exit 1).
    pub fn usage(msg: impl Into<String>) -> Self {
        Self {
            code: 1,
            msg: msg.into(),
        }
    }

    /// I/O error (exit 2).
    pub fn io(msg: impl Into<String>) -> Self {
        Self {
            code: 2,
            msg: msg.into(),
        }
    }

    /// Prefix the message with context (e.g. a file name).
    pub fn context(mut self, ctx: impl AsRef<str>) -> Self {
        self.msg = format!("{}: {}", ctx.as_ref(), self.msg);
        self
    }
}

impl From<secreto_core::Error> for CliError {
    fn from(e: secreto_core::Error) -> Self {
        Self {
            code: e.exit_code(),
            msg: e.to_string(),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        Self::io(e.to_string())
    }
}

/// Result alias for CLI operations.
pub type Result<T> = std::result::Result<T, CliError>;

/// Print `prog: error: <msg>` (single line) to stderr and exit.
pub fn die(prog: &str, e: &CliError) -> ! {
    let one_line: String = e
        .msg
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    eprintln!("{prog}: error: {one_line}");
    std::process::exit(e.code)
}

/// Print `prog: warning: <msg>` to stderr.
pub fn warn(prog: &str, msg: &str) {
    eprintln!("{prog}: warning: {msg}");
}

/// Is `path` absent or `-` (stdin/stdout)?
pub fn is_std(path: Option<&str>) -> bool {
    matches!(path, None | Some("-"))
}

/// Read all of stdin or the file at `path`.
pub fn read_input(path: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    if is_std(path) {
        io::stdin()
            .lock()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::io(format!("reading stdin: {e}")))?;
    } else {
        let p = path.expect("checked");
        File::open(p)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| CliError::io(format!("{p}: {e}")))?;
    }
    Ok(buf)
}

/// Read a UTF-8 text file (recipients, identities, keys).
pub fn read_text_file(path: &Path) -> Result<Zeroizing<String>> {
    let name = path.display().to_string();
    let bytes = fs::read(path).map_err(|e| CliError::io(format!("{name}: {e}")))?;
    let bytes = Zeroizing::new(bytes);
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::usage(format!("{name}: not valid UTF-8")))?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Read a secret key file, warning when it is group/world accessible.
pub fn read_secret_key_file(prog: &str, path: &Path) -> Result<Zeroizing<String>> {
    if let Ok(md) = fs::metadata(path) {
        if md.permissions().mode() & 0o077 != 0 {
            warn(
                prog,
                &format!(
                    "{} is group- or world-readable; consider chmod 600",
                    path.display()
                ),
            );
        }
    }
    read_text_file(path)
}

/// Read a secret key from a path, or stdin when `path` is `None` / `-`.
pub fn read_secret_key_input(prog: &str, path: Option<&str>) -> Result<Zeroizing<String>> {
    if is_std(path) {
        let bytes = read_input(None)?;
        let s =
            std::str::from_utf8(&bytes).map_err(|_| CliError::usage("stdin: not valid UTF-8"))?;
        Ok(Zeroizing::new(s.to_owned()))
    } else {
        read_secret_key_file(prog, Path::new(path.expect("checked")))
    }
}

fn strip_line_ending(buf: &mut Vec<u8>, saw_lf: bool) {
    if saw_lf && buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
}

fn read_passphrase_fd(fd_str: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::fd::{FromRawFd, RawFd};
    let fd: RawFd = fd_str
        .parse::<u32>()
        .ok()
        .and_then(|n| RawFd::try_from(n).ok())
        .filter(|_| !fd_str.is_empty() && fd_str.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            CliError::usage(format!("{ENV_PASSPHRASE_FD} must be a decimal fd number"))
        })?;
    // SAFETY: the caller designates this descriptor via the environment and
    // transfers ownership to us; it is closed when `file` is dropped.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut reader = io::BufReader::new(file.take(MAX_PASSPHRASE_LEN));
    let mut buf = Zeroizing::new(Vec::new());
    reader
        .read_until(b'\n', &mut buf)
        .map_err(|e| CliError::io(format!("reading passphrase from fd {fd}: {e}")))?;
    let saw_lf = buf.last() == Some(&b'\n');
    strip_line_ending(&mut buf, saw_lf);
    Ok(buf)
}

fn read_passphrase_tty(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut tty = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            CliError::usage(format!(
                "no terminal available; set {ENV_PASSPHRASE_FD} to read the passphrase from a descriptor"
            ))
        })?;
    let _ = write!(tty, "{prompt}");
    let _ = tty.flush();
    let pw = rpassword::read_password()
        .map_err(|e| CliError::io(format!("reading passphrase from terminal: {e}")))?;
    Ok(Zeroizing::new(pw.into_bytes()))
}

/// Obtain a passphrase from `SECRETO_PASSPHRASE_FD` or `/dev/tty`. With
/// `confirm`, the terminal path asks twice and requires equality.
pub fn read_passphrase(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    match std::env::var(ENV_PASSPHRASE_FD) {
        Ok(v) => read_passphrase_fd(&v),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::usage(format!(
            "{ENV_PASSPHRASE_FD} must be a decimal fd number"
        ))),
        Err(std::env::VarError::NotPresent) => {
            let first = read_passphrase_tty("Passphrase: ")?;
            if confirm {
                let second = read_passphrase_tty("Confirm passphrase: ")?;
                if *first != *second {
                    return Err(CliError::usage("passphrases do not match"));
                }
            }
            Ok(first)
        }
    }
}

/// Write `data` to stdout.
pub fn write_stdout(data: &[u8]) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(data)
        .and_then(|()| out.flush())
        .map_err(|e| CliError::io(format!("writing stdout: {e}")))
}

/// Removes the temporary file unless committed.
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_temp(target: &Path) -> Result<(File, PathBuf)> {
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let base = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| CliError::usage(format!("{}: invalid output path", target.display())))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    for attempt in 0..64u32 {
        let tmp = dir.join(format!(
            ".{base}.tmp.{}.{nanos:08x}.{attempt}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => return Ok((f, tmp)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CliError::io(format!("{}: {e}", tmp.display()))),
        }
    }
    Err(CliError::io("could not create a temporary output file"))
}

/// Write `data` to `out` (`None` / `-` is stdout). Files are written to an
/// `O_EXCL` mode-0600 temporary in the same directory, fsynced, and renamed
/// into place; the temporary is unlinked on failure.
pub fn write_output(out: Option<&str>, data: &[u8]) -> Result<()> {
    if is_std(out) {
        return write_stdout(data);
    }
    let target = Path::new(out.expect("checked"));
    let (mut file, tmp) = create_temp(target)?;
    let mut guard = TempGuard {
        path: tmp,
        armed: true,
    };
    let name = target.display().to_string();
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|e| CliError::io(format!("{name}: {e}")))?;
    drop(file);
    fs::rename(&guard.path, target).map_err(|e| CliError::io(format!("{name}: {e}")))?;
    guard.armed = false;
    Ok(())
}

/// Create a new secret key file at `path` (mode 0600, must not exist) and
/// write `data` to it.
pub fn write_new_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    let name = path.display().to_string();
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::io(format!("{name}: {e}")))?;
    let r = f
        .write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| CliError::io(format!("{name}: {e}")));
    if r.is_err() {
        drop(f);
        let _ = fs::remove_file(path);
    }
    r
}

/// Lower-case hexadecimal encoding.
pub fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
