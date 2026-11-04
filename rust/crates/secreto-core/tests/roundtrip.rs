// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

//! End-to-end tests of the secreto/v1 format using the public API.

use secreto_core::argon::{self, ArgonParams};
use secreto_core::encrypt::{encrypt_with_stanzas, mlkem_stanza};
use secreto_core::header::{self, Stanza};
use secreto_core::{
    armor, decrypt, decrypt_to, encrypt, encrypt_armored, encrypt_to, inner, padme, stream,
    DecryptOptions, EncryptOptions, Error, Identity, Recipients, SigningKey,
};

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 % 256) as u8).collect()
}

fn opts<'a>(ids: &'a [Identity]) -> DecryptOptions<'a> {
    DecryptOptions {
        identities: ids,
        ..Default::default()
    }
}

const LOW: ArgonParams = ArgonParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

#[test]
fn single_recipient_roundtrip_many_sizes() {
    let id = Identity::generate().unwrap();
    let rcpt = id.recipient().unwrap();
    let ids = [id];
    // 65534 -> inner of exactly one full chunk; 65535 -> a 1-byte second chunk.
    for n in [0usize, 1, 2, 1000, 65_533, 65_534, 65_535, 65_536, 200_000] {
        let pt = data(n);
        let ct = encrypt(
            &pt,
            Recipients::Keys(std::slice::from_ref(&rcpt)),
            &EncryptOptions::default(),
        )
        .unwrap();
        assert!(ct.starts_with(b"secreto/v1\n-> mlkem1024p384 "), "n={n}");
        let out = decrypt(&ct, &opts(&ids)).unwrap();
        assert_eq!(&out.content[..], &pt[..], "n={n}");
        assert!(out.signer_id.is_none());
        assert!(!out.verified);
    }
}

#[test]
fn multiple_recipients_each_can_decrypt() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let c = Identity::generate().unwrap();
    let rcpts = [a.recipient().unwrap(), b.recipient().unwrap()];
    let ct = encrypt(
        b"shared",
        Recipients::Keys(&rcpts),
        &EncryptOptions::default(),
    )
    .unwrap();
    let (h, _) = header::parse(&ct).unwrap();
    assert_eq!(h.stanzas.len(), 2);
    assert_eq!(&decrypt(&ct, &opts(&[a])).unwrap().content[..], b"shared");
    assert_eq!(&decrypt(&ct, &opts(&[b])).unwrap().content[..], b"shared");
    let err = decrypt(&ct, &opts(&[c])).unwrap_err();
    assert_eq!(err, Error::NoMatch);
    assert_eq!(err.exit_code(), 3);
    // several identities, only the last matches
    let x = Identity::generate().unwrap();
    let y = Identity::generate().unwrap();
    let again = Identity::from_seed(*y.seed());
    let ct = encrypt(
        b"z",
        Recipients::Keys(&[y.recipient().unwrap()]),
        &EncryptOptions::default(),
    )
    .unwrap();
    assert!(decrypt(&ct, &opts(&[x, again])).is_ok());
}

#[test]
fn armored_roundtrip() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let s = encrypt_armored(
        &data(5000),
        Recipients::Keys(&[ids[0].recipient().unwrap()]),
        &EncryptOptions::default(),
    )
    .unwrap();
    assert!(s.starts_with("-----BEGIN SECRETO ENCRYPTED FILE-----\n"));
    assert_eq!(
        &decrypt(s.as_bytes(), &opts(&ids)).unwrap().content[..],
        &data(5000)[..]
    );
    // CRLF armor accepted, junk rejected
    let crlf = s.replace('\n', "\r\n");
    assert!(decrypt(crlf.as_bytes(), &opts(&ids)).is_ok());
    let junk = format!("{s}junk");
    assert_eq!(
        decrypt(junk.as_bytes(), &opts(&ids))
            .unwrap_err()
            .exit_code(),
        4
    );
    let _ = armor::LABEL;
}

#[test]
fn padding_hides_length() {
    let id = Identity::generate().unwrap();
    let r = [id.recipient().unwrap()];
    let ids = [id];
    let no_pad = EncryptOptions::default();
    let pad = EncryptOptions {
        pad: true,
        ..Default::default()
    };
    let (h_len, _) = {
        let c = encrypt(b"x", Recipients::Keys(&r), &no_pad).unwrap();
        let (_, l) = header::parse(&c).unwrap();
        (l, ())
    };
    for n in [1usize, 10, 100, 1000, 70_000] {
        let pt = data(n);
        let c0 = encrypt(&pt, Recipients::Keys(&r), &no_pad).unwrap();
        let c1 = encrypt(&pt, Recipients::Keys(&r), &pad).unwrap();
        let payload = |c: &[u8]| c.len() - header::parse(c).unwrap().1;
        let chunks = |inner: usize| inner.div_ceil(stream::CHUNK_SIZE);
        let inner0 = n + 2;
        let inner1 = padme::padme(inner0 as u64) as usize;
        assert_eq!(payload(&c0), 16 + inner0 + 16 * chunks(inner0));
        assert_eq!(payload(&c1), 16 + inner1 + 16 * chunks(inner1));
        assert_eq!(&decrypt(&c1, &opts(&ids)).unwrap().content[..], &pt[..]);
    }
    assert!(h_len > 2000); // 1665-byte enc is base64'd into the header
}

#[test]
fn tampering_is_detected() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let ct = encrypt(
        &data(300),
        Recipients::Keys(&[ids[0].recipient().unwrap()]),
        &EncryptOptions::default(),
    )
    .unwrap();
    let (_, hlen) = header::parse(&ct).unwrap();

    // payload bit flips and truncation -> exit 4
    for pos in [hlen, hlen + 20, ct.len() - 1] {
        let mut t = ct.clone();
        t[pos] ^= 1;
        assert_eq!(
            decrypt(&t, &opts(&ids)).unwrap_err().exit_code(),
            4,
            "pos={pos}"
        );
    }
    assert_eq!(
        decrypt(&ct[..ct.len() - 1], &opts(&ids))
            .unwrap_err()
            .exit_code(),
        4
    );
    assert_eq!(
        decrypt(&ct[..hlen], &opts(&ids)).unwrap_err().exit_code(),
        4
    );
    let mut ext = ct.clone();
    ext.push(0);
    assert_eq!(decrypt(&ext, &opts(&ids)).unwrap_err().exit_code(), 4);

    // flip a bit in the MAC value (last base64 char region)
    let mut t = ct.clone();
    t[hlen - 3] = if t[hlen - 3] == b'A' { b'B' } else { b'A' };
    assert!(decrypt(&t, &opts(&ids)).is_err());

    // add an unknown stanza after the fact: header MAC must fail
    let (h, _) = header::parse(&ct).unwrap();
    let mut stanzas = h.stanzas.clone();
    stanzas.push(Stanza {
        args: vec!["extra".into()],
        body: vec![],
    });
    let (new_hdr, _) = header::marshal(&stanzas, &[0u8; 32]).unwrap(); // wrong key => wrong MAC
    let mut forged = new_hdr;
    forged.extend_from_slice(&ct[hlen..]);
    assert_eq!(decrypt(&forged, &opts(&ids)).unwrap_err().exit_code(), 4);

    // tamper with the stanza body (not the MAC) -> HPKE fails => no match
    let mut t = ct.clone();
    let nl = t.iter().position(|&b| b == b'\n').unwrap(); // after version
    let arg_end = nl + 1 + t[nl + 1..].iter().position(|&b| b == b'\n').unwrap();
    let body_pos = arg_end + 1;
    t[body_pos] = if t[body_pos] == b'A' { b'B' } else { b'A' };
    assert!(matches!(
        decrypt(&t, &opts(&ids)).unwrap_err(),
        Error::NoMatch | Error::Format(_)
    ));
}

#[test]
fn unknown_stanzas_ignored_and_malformed_mlkem_skipped() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let fk = [0x77u8; 32];
    let good = mlkem_stanza(&ids[0].recipient().unwrap(), &fk).unwrap();
    let unknown = Stanza {
        args: vec!["x25519".into(), "AAAA".into()],
        body: vec![1, 2, 3],
    };

    let ct = encrypt_with_stanzas(
        &fk,
        &[unknown.clone(), good.clone()],
        b"payload",
        &EncryptOptions::default(),
    )
    .unwrap();
    assert_eq!(&decrypt(&ct, &opts(&ids)).unwrap().content[..], b"payload");

    // malformed mlkem stanzas: wrong arg count, bad body length, bad enc
    let mut bad_args = good.clone();
    bad_args.args.push("extra".into());
    let mut bad_body = good.clone();
    bad_body.body.pop();
    let mut bad_enc = good.clone();
    bad_enc.args[1] = "AAAA".into();
    for bad in [bad_args, bad_body, bad_enc] {
        let ct = encrypt_with_stanzas(
            &fk,
            std::slice::from_ref(&bad),
            b"p",
            &EncryptOptions::default(),
        )
        .unwrap();
        assert_eq!(decrypt(&ct, &opts(&ids)).unwrap_err(), Error::NoMatch);
        // ... but a valid stanza later in the header still works
        let ct = encrypt_with_stanzas(&fk, &[bad, good.clone()], b"p", &EncryptOptions::default())
            .unwrap();
        assert!(decrypt(&ct, &opts(&ids)).is_ok());
    }

    // only unknown stanzas => no match
    let ct = encrypt_with_stanzas(&fk, &[unknown], b"p", &EncryptOptions::default()).unwrap();
    assert_eq!(decrypt(&ct, &opts(&ids)).unwrap_err(), Error::NoMatch);
}

#[test]
fn passphrase_roundtrip_and_rules() {
    let fk = [0x31u8; 32];
    let st = argon::wrap_with(b"hunter2", &fk, &[9u8; 16], LOW).unwrap();
    let ct = encrypt_with_stanzas(
        &fk,
        std::slice::from_ref(&st),
        b"secret text",
        &EncryptOptions::default(),
    )
    .unwrap();

    let ok = decrypt(
        &ct,
        &DecryptOptions {
            passphrase: Some(b"hunter2"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(&ok.content[..], b"secret text");

    let bad = decrypt(
        &ct,
        &DecryptOptions {
            passphrase: Some(b"hunter3"),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(bad, Error::NoMatch);

    // identity-only decryption of a passphrase file => no match
    let id = Identity::generate().unwrap();
    assert_eq!(decrypt(&ct, &opts(&[id])).unwrap_err(), Error::NoMatch);

    // argon2id mixed with another stanza => exit 4
    let id = Identity::generate().unwrap();
    let mk = mlkem_stanza(&id.recipient().unwrap(), &fk).unwrap();
    let mixed =
        encrypt_with_stanzas(&fk, &[st.clone(), mk], b"x", &EncryptOptions::default()).unwrap();
    let e = decrypt(
        &mixed,
        &DecryptOptions {
            passphrase: Some(b"hunter2"),
            identities: &[id],
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 4);

    // out-of-range parameter in the stanza => exit 4
    let mut weak = st.clone();
    weak.args[2] = "1024".into();
    let ct = encrypt_with_stanzas(&fk, &[weak], b"x", &EncryptOptions::default()).unwrap();
    let e = decrypt(
        &ct,
        &DecryptOptions {
            passphrase: Some(b"hunter2"),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 4);
}

#[test]
fn streaming_matches_in_memory() {
    use std::io::Cursor;
    let id = Identity::generate().unwrap();
    let ids = [id];
    let r = [ids[0].recipient().unwrap()];
    let sk = SigningKey::generate().unwrap();
    for (pad, sign, n) in [
        (false, false, 0usize),
        (false, false, 100),
        (true, false, 1000),
        (false, true, 70_000),
        (true, true, 100),
    ] {
        let pt = data(n);
        let opts = EncryptOptions {
            pad,
            signer: sign.then_some(&sk),
            ..Default::default()
        };
        let mem = encrypt(&pt, Recipients::Keys(&r), &opts).unwrap();
        let mut out = Vec::new();
        encrypt_to(
            &mut Cursor::new(&pt),
            &mut out,
            Recipients::Keys(&r),
            &opts,
        )
        .unwrap();
        // Nonces and ephemeral keys differ; compare via decrypt.
        let a = decrypt(&mem, &opts_ids(&ids, sign.then_some(&sk.public_key()))).unwrap();
        let b = decrypt(&out, &opts_ids(&ids, sign.then_some(&sk.public_key()))).unwrap();
        assert_eq!(&a.content[..], &pt[..], "pad={pad} sign={sign} n={n}");
        assert_eq!(&b.content[..], &pt[..], "pad={pad} sign={sign} n={n}");

        let mut recovered = Vec::new();
        let meta = decrypt_to(
            &mut Cursor::new(&out),
            &mut recovered,
            &opts_ids(&ids, sign.then_some(&sk.public_key())),
        )
        .unwrap();
        assert_eq!(recovered, pt);
        assert_eq!(meta.verified, sign);
    }

    // Passphrase streaming at default 64 MiB.
    let opts = EncryptOptions::default();
    let mut out = Vec::new();
    encrypt_to(
        &mut Cursor::new(b"stream-pw"),
        &mut out,
        Recipients::Passphrase(b"pw"),
        &opts,
    )
    .unwrap();
    let (h, _) = header::parse(&out).unwrap();
    assert_eq!(&h.stanzas[0].args[2..], &["65536", "3", "4"]);
    let mut recovered = Vec::new();
    decrypt_to(
        &mut Cursor::new(&out),
        &mut recovered,
        &DecryptOptions {
            passphrase: Some(b"pw"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(recovered, b"stream-pw");
}

fn opts_ids<'a>(
    ids: &'a [Identity],
    verify: Option<&'a secreto_core::SignerPublicKey>,
) -> DecryptOptions<'a> {
    DecryptOptions {
        identities: ids,
        verify,
        ..Default::default()
    }
}

#[test]
fn passphrase_default_parameters() {
    let ct = encrypt(
        b"hello",
        Recipients::Passphrase(b"pw"),
        &EncryptOptions::default(),
    )
    .unwrap();
    let (h, _) = header::parse(&ct).unwrap();
    assert_eq!(&h.stanzas[0].args[2..], &["65536", "3", "4"]);
    let out = decrypt(
        &ct,
        &DecryptOptions {
            passphrase: Some(b"pw"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(&out.content[..], b"hello");
}

#[test]
#[ignore = "uses 1 GiB Argon2id; run with --release -- --ignored"]
fn passphrase_high_memory_parameters() {
    let opts = EncryptOptions {
        argon: argon::ArgonParams {
            m_kib: 1_048_576,
            t: 3,
            p: 4,
        },
        ..Default::default()
    };
    let ct = encrypt(b"hello", Recipients::Passphrase(b"pw"), &opts).unwrap();
    let (h, _) = header::parse(&ct).unwrap();
    assert_eq!(&h.stanzas[0].args[2..], &["1048576", "3", "4"]);
}

#[test]
fn signing_and_verification() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let r = [ids[0].recipient().unwrap()];
    let sk = SigningKey::generate().unwrap();
    let pk = sk.public_key();
    let other_pk = SigningKey::generate().unwrap().public_key();

    for pad in [false, true] {
        for n in [0usize, 5, 70_000] {
            let pt = data(n);
            let ct = encrypt(
                &pt,
                Recipients::Keys(&r),
                &EncryptOptions {
                    pad,
                    signer: Some(&sk),
                    ..Default::default()
                },
            )
            .unwrap();

            // verify OK
            let out = decrypt(
                &ct,
                &DecryptOptions {
                    identities: &ids,
                    verify: Some(&pk),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(&out.content[..], &pt[..]);
            assert!(out.verified);
            assert_eq!(out.signer_id, Some(pk.signer_id()));

            // no --verify: released with signer id, unverified
            let out = decrypt(&ct, &opts(&ids)).unwrap();
            assert_eq!(&out.content[..], &pt[..]);
            assert!(!out.verified);
            assert_eq!(out.signer_id, Some(pk.signer_id()));

            // wrong signer => exit 5
            let e = decrypt(
                &ct,
                &DecryptOptions {
                    identities: &ids,
                    verify: Some(&other_pk),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert_eq!(e.exit_code(), 5);
        }
    }

    // unsigned file with --verify => exit 5
    let ct = encrypt(b"x", Recipients::Keys(&r), &EncryptOptions::default()).unwrap();
    let e = decrypt(
        &ct,
        &DecryptOptions {
            identities: &ids,
            verify: Some(&pk),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 5);
}

/// A signature bound to one header must not verify when the same inner
/// plaintext is moved under a different header / file key.
#[test]
fn signature_is_bound_to_header_mac() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let sk = SigningKey::generate().unwrap();
    let pk = sk.public_key();
    let ct = encrypt(
        b"bound",
        Recipients::Keys(&[ids[0].recipient().unwrap()]),
        &EncryptOptions {
            pad: false,
            signer: Some(&sk),
            ..Default::default()
        },
    )
    .unwrap();
    // Extract the inner plaintext and re-wrap under a fresh file key.
    let (h, hlen) = header::parse(&ct).unwrap();
    let _ = h;
    // Re-encrypt: sign over a *different* header MAC by constructing the
    // inner by hand using the first file's signature.
    let fk2 = [0x99u8; 32];
    let st2 = mlkem_stanza(&ids[0].recipient().unwrap(), &fk2).unwrap();
    let (hdr2, _mac2) = header::marshal(&[st2], &fk2).unwrap();
    // Recover the old inner via decrypting with the original keys.
    let old = decrypt(&ct, &opts(&ids)).unwrap();
    assert_eq!(&old.content[..], b"bound");
    let _ = hlen;
    // Build inner with the old sigblock (taken from the original payload).
    let fk_old = {
        let (h, _) = header::parse(&ct).unwrap();
        // Unwrap using HPKE to get the original file key.
        let s = &h.stanzas[0];
        let enc = base64_decode(&s.args[1]);
        let pt = secreto_core::hpke::open_base(
            &enc,
            ids[0].seed(),
            secreto_core::hpke::INFO,
            b"",
            &s.body,
        )
        .unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&pt);
        k
    };
    let plain = stream::decrypt(&fk_old, &ct[hlen..]).unwrap();
    let nonce = [5u8; 16];
    let payload = stream::encrypt(&fk2, &nonce, &plain).unwrap();
    let mut spliced = hdr2;
    spliced.extend_from_slice(&payload);
    let e = decrypt(
        &spliced,
        &DecryptOptions {
            identities: &ids,
            verify: Some(&pk),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 5);
    // Unverified decryption still works (and reports the signer).
    assert!(decrypt(&spliced, &opts(&ids)).is_ok());
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD.decode(s).unwrap()
}

#[test]
fn malformed_inner_plaintext_rejected_with_exit_4() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    let fk = [0x12u8; 32];
    let good = mlkem_stanza(&ids[0].recipient().unwrap(), &fk).unwrap();
    let (hdr, _) = header::marshal(&[good], &fk).unwrap();

    let build = |inner_bytes: &[u8]| {
        let mut f = hdr.clone();
        f.extend_from_slice(&stream::encrypt(&fk, &[1u8; 16], inner_bytes).unwrap());
        f
    };

    // bad flags
    assert_eq!(
        decrypt(&build(&[2, 0x80]), &opts(&ids))
            .unwrap_err()
            .exit_code(),
        4
    );
    // no terminator
    assert_eq!(
        decrypt(&build(&[0, 1, 2]), &opts(&ids))
            .unwrap_err()
            .exit_code(),
        4
    );
    // claims signed but truncated sigblock
    let mut short = vec![1u8, b'a', 0x80];
    short.extend_from_slice(&[0u8; 100]);
    assert_eq!(
        decrypt(&build(&short), &opts(&ids))
            .unwrap_err()
            .exit_code(),
        4
    );
    // a single byte
    assert_eq!(
        decrypt(&build(&[0]), &opts(&ids)).unwrap_err().exit_code(),
        4
    );
    // valid
    let ok = inner::build(b"fine", None, false);
    assert!(decrypt(&build(&ok), &opts(&ids)).is_ok());
}

#[test]
fn version_and_garbage_rejected() {
    let id = Identity::generate().unwrap();
    let ids = [id];
    for bad in [
        &b""[..],
        b"secreto/v2\n",
        b"hello world",
        b"age-encryption.org/v1\n",
    ] {
        assert_eq!(decrypt(bad, &opts(&ids)).unwrap_err().exit_code(), 4);
    }
}

#[test]
fn encrypt_rejects_bad_recipient_sets() {
    let e = encrypt(b"x", Recipients::Keys(&[]), &EncryptOptions::default()).unwrap_err();
    assert_eq!(e.exit_code(), 1);
    let id = Identity::generate().unwrap();
    let r = id.recipient().unwrap();
    let many: Vec<_> = (0..=header::MAX_STANZAS).map(|_| r.clone()).collect();
    let e = encrypt(b"x", Recipients::Keys(&many), &EncryptOptions::default()).unwrap_err();
    assert_eq!(e.exit_code(), 1);
}
