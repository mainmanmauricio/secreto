// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! End-to-end tests of the `secreto` and `secreto-keygen` binaries.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("secreto-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn run(bin: &str, args: &[&str], stdin: Option<&[u8]>) -> (i32, Vec<u8>, String) {
    use std::io::Write;
    let mut c = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut si = c.stdin.take().unwrap();
    if let Some(d) = stdin {
        si.write_all(d).unwrap();
    }
    drop(si);
    let o = c.wait_with_output().unwrap();
    (
        o.status.code().unwrap(),
        o.stdout,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

const SECRETO: &str = env!("CARGO_BIN_EXE_secreto");
const KEYGEN: &str = env!("CARGO_BIN_EXE_secreto-keygen");

#[test]
fn keygen_encrypt_decrypt_roundtrip() {
    let d = tmpdir("roundtrip");
    let key = d.join("id.key");
    let (code, _, rcpt) = run(KEYGEN, &["-o", key.to_str().unwrap()], None);
    assert_eq!(code, 0);
    let rcpt = rcpt.trim().to_string();
    assert!(rcpt.starts_with("secreto1"));
    let (code, y, _) = run(KEYGEN, &["-y", key.to_str().unwrap()], None);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(y).unwrap().trim(), rcpt);

    let (code, ct, err) = run(SECRETO, &["-r", &rcpt], Some(b"hello cli"));
    assert_eq!(code, 0, "{err}");
    let (code, pt, err) = run(SECRETO, &["-d", "-i", key.to_str().unwrap()], Some(&ct));
    assert_eq!(code, 0, "{err}");
    assert_eq!(pt, b"hello cli");

    // armored, -o, padded
    let out = d.join("out.asc");
    let (code, _, err) = run(
        SECRETO,
        &["-a", "--pad", "-r", &rcpt, "-o", out.to_str().unwrap()],
        Some(b"x"),
    );
    assert_eq!(code, 0, "{err}");
    assert!(fs::read_to_string(&out)
        .unwrap()
        .starts_with("-----BEGIN SECRETO ENCRYPTED FILE-----"));
    let (code, pt, _) = run(
        SECRETO,
        &["-d", "-i", key.to_str().unwrap(), out.to_str().unwrap()],
        None,
    );
    assert_eq!((code, pt.as_slice()), (0, &b"x"[..]));
}

#[test]
fn exit_codes_and_error_format() {
    let (code, _, err) = run(SECRETO, &[], None);
    assert_eq!(code, 1);
    assert!(err.starts_with("secreto: error: "));
    assert_eq!(err.trim_end().lines().count(), 1);

    let (code, _, _) = run(SECRETO, &["-d", "-i", "/nonexistent/key"], None);
    assert_eq!(code, 2);

    let d = tmpdir("codes");
    let k1 = d.join("k1");
    let k2 = d.join("k2");
    let (_, _, r1) = run(KEYGEN, &["-o", k1.to_str().unwrap()], None);
    run(KEYGEN, &["-o", k2.to_str().unwrap()], None);
    let (_, ct, _) = run(SECRETO, &["-r", r1.trim()], Some(b"data"));
    let (code, out, _) = run(SECRETO, &["-d", "-i", k2.to_str().unwrap()], Some(&ct));
    assert_eq!(code, 3);
    assert!(out.is_empty());

    let mut bad = ct.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    let (code, out, _) = run(SECRETO, &["-d", "-i", k1.to_str().unwrap()], Some(&bad));
    assert_eq!(code, 4);
    assert!(out.is_empty());
}

#[test]
fn signing_and_verify() {
    let d = tmpdir("sign");
    let key = d.join("id");
    let sk = d.join("sig");
    let sk2 = d.join("sig2");
    let (_, _, rcpt) = run(KEYGEN, &["-o", key.to_str().unwrap()], None);
    let (_, _, pubkey) = run(KEYGEN, &["--signing", "-o", sk.to_str().unwrap()], None);
    let (_, _, other) = run(KEYGEN, &["--signing", "-o", sk2.to_str().unwrap()], None);
    let (code, ct, err) = run(
        SECRETO,
        &["-r", rcpt.trim(), "--sign", sk.to_str().unwrap()],
        Some(b"signed"),
    );
    assert_eq!(code, 0, "{err}");

    let (code, pt, err) = run(SECRETO, &["-d", "-i", key.to_str().unwrap()], Some(&ct));
    assert_eq!((code, pt.as_slice()), (0, &b"signed"[..]));
    assert!(err.contains("signer_id"), "{err}");

    let (code, pt, _) = run(
        SECRETO,
        &["-d", "-i", key.to_str().unwrap(), "--verify", pubkey.trim()],
        Some(&ct),
    );
    assert_eq!((code, pt.as_slice()), (0, &b"signed"[..]));

    let (code, pt, _) = run(
        SECRETO,
        &["-d", "-i", key.to_str().unwrap(), "--verify", other.trim()],
        Some(&ct),
    );
    assert_eq!(code, 5);
    assert!(pt.is_empty());

    // Failed verification leaves no output file behind.
    let out = d.join("out");
    let (code, _, _) = run(
        SECRETO,
        &[
            "-d",
            "-i",
            key.to_str().unwrap(),
            "--verify",
            other.trim(),
            "-o",
            out.to_str().unwrap(),
        ],
        Some(&ct),
    );
    assert_eq!(code, 5);
    assert!(!out.exists());
    let leftovers: Vec<_> = fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn keygen_files_are_private_and_not_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("perm");
    let key = d.join("k");
    assert_eq!(run(KEYGEN, &["-o", key.to_str().unwrap()], None).0, 0);
    let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(run(KEYGEN, &["-o", key.to_str().unwrap()], None).0, 2);
}
