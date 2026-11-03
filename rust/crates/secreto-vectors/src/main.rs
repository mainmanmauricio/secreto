//! Deterministic whole-file test-kit generator for secreto/v1.
//!
//! ```text
//! secreto-vectors generate <outdir>
//! secreto-vectors check <outdir>
//! ```
//!
//! All "random" values (file keys, KEM randomness, salts, nonces, content)
//! come from per-vector seeded ChaCha20 streams, and signatures use the
//! deterministic ML-DSA variant, so output is byte-for-byte reproducible.
//! The seeded RNG exists **only** in this crate.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20::ChaCha20Rng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand_core::{Rng, SeedableRng};
use secreto_core::argon::{self, ArgonParams};
use secreto_core::header::{self, Stanza, TYPE_MLKEM};
use secreto_core::sign::{signature_message, SigBlock};
use secreto_core::{
    armor, decrypt, hpke, inner, kem, stream, DecryptOptions, Identity, Recipient, SignerPublicKey,
    SigningKey,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Vector model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    Success,
    NoMatch,
    HeaderFailure,
    PayloadFailure,
    SignatureFailure,
}

impl Expect {
    fn as_str(self) -> &'static str {
        match self {
            Expect::Success => "success",
            Expect::NoMatch => "no-match",
            Expect::HeaderFailure => "header-failure",
            Expect::PayloadFailure => "payload-failure",
            Expect::SignatureFailure => "signature-failure",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "success" => Expect::Success,
            "no-match" => Expect::NoMatch,
            "header-failure" => Expect::HeaderFailure,
            "payload-failure" => Expect::PayloadFailure,
            "signature-failure" => Expect::SignatureFailure,
            _ => return None,
        })
    }

    /// CLI exit code a conforming implementation produces.
    fn exit_code(self) -> i32 {
        match self {
            Expect::Success => 0,
            Expect::NoMatch => 3,
            Expect::HeaderFailure | Expect::PayloadFailure => 4,
            Expect::SignatureFailure => 5,
        }
    }
}

#[derive(Clone, Debug)]
struct Meta {
    expect: Expect,
    identities: Vec<String>,
    passphrase: Option<String>,
    verify: Option<String>,
    payload: Option<Vec<u8>>,
    armored: bool,
}

impl Meta {
    fn new(expect: Expect) -> Self {
        Self {
            expect,
            identities: Vec::new(),
            passphrase: None,
            verify: None,
            payload: None,
            armored: false,
        }
    }
    fn id(mut self, id: &str) -> Self {
        self.identities.push(id.to_string());
        self
    }
    fn pass(mut self, p: &str) -> Self {
        self.passphrase = Some(p.to_string());
        self
    }
    fn verify(mut self, v: &str) -> Self {
        self.verify = Some(v.to_string());
        self
    }
    fn payload(mut self, p: &[u8]) -> Self {
        self.payload = Some(p.to_vec());
        self
    }
    fn armored(mut self) -> Self {
        self.armored = true;
        self
    }
}

struct TestVec {
    name: String,
    meta: Meta,
    body: Vec<u8>,
}

impl TestVec {
    fn to_bytes(&self) -> Vec<u8> {
        let m = &self.meta;
        let mut s = format!("expect: {}\n", m.expect.as_str());
        for id in &m.identities {
            s.push_str(&format!("identity: {id}\n"));
        }
        if let Some(p) = &m.passphrase {
            s.push_str(&format!("passphrase: {p}\n"));
        }
        if let Some(v) = &m.verify {
            s.push_str(&format!("verify: {v}\n"));
        }
        if let Some(p) = &m.payload {
            s.push_str(&format!("payload: {}\n", hex::encode(p)));
        }
        if m.armored {
            s.push_str("armored: yes\n");
        }
        s.push('\n');
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

fn parse_vector(bytes: &[u8]) -> Result<(Meta, Vec<u8>), String> {
    let split = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or("no blank line after metadata")?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| "metadata not UTF-8")?;
    let body = bytes[split + 2..].to_vec();
    let mut meta = Meta::new(Expect::Success);
    let mut have_expect = false;
    for line in head.lines() {
        let (k, v) = line.split_once(": ").ok_or("bad metadata line")?;
        match k {
            "expect" => {
                meta.expect = Expect::parse(v).ok_or("bad expect")?;
                have_expect = true;
            }
            "identity" => meta.identities.push(v.to_string()),
            "passphrase" => meta.passphrase = Some(v.to_string()),
            "verify" => meta.verify = Some(v.to_string()),
            "payload" => meta.payload = Some(hex::decode(v).map_err(|_| "bad payload hex")?),
            "armored" => meta.armored = v == "yes",
            _ => return Err(format!("unknown metadata key {k}")),
        }
    }
    if !have_expect {
        return Err("missing expect".into());
    }
    Ok((meta, body))
}

/// Decrypt a vector with `secreto-core` and compare with its expectation.
fn conformance(name: &str, bytes: &[u8]) -> Result<(), String> {
    let (meta, body) = parse_vector(bytes).map_err(|e| format!("{name}: {e}"))?;
    let ids: Vec<Identity> = meta
        .identities
        .iter()
        .map(|s| Identity::from_bech32(s).map_err(|e| format!("{name}: {e}")))
        .collect::<Result<_, _>>()?;
    let verify: Option<SignerPublicKey> = meta
        .verify
        .as_deref()
        .map(|s| SignerPublicKey::from_bech32(s).map_err(|e| format!("{name}: {e}")))
        .transpose()?;
    let opts = DecryptOptions {
        identities: &ids,
        passphrase: meta.passphrase.as_deref().map(str::as_bytes),
        verify: verify.as_ref(),
    };
    let got = decrypt(&body, &opts);
    let code = match &got {
        Ok(_) => 0,
        Err(e) => e.exit_code(),
    };
    if code != meta.expect.exit_code() {
        return Err(format!(
            "{name}: expected {} (exit {}), got {:?}",
            meta.expect.as_str(),
            meta.expect.exit_code(),
            got.map(|d| d.content.len())
        ));
    }
    if let (Ok(d), Some(p)) = (&got, &meta.payload) {
        if d.content[..] != p[..] {
            return Err(format!("{name}: payload mismatch"));
        }
    }
    if meta.expect == Expect::Success && meta.armored != armor::is_armored(&body) {
        return Err(format!("{name}: armored flag does not match file"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic building blocks
// ---------------------------------------------------------------------------

fn rng_for(label: &str) -> ChaCha20Rng {
    let seed: [u8; 32] = Sha256::digest(format!("secreto/v1/testkit/{label}").as_bytes()).into();
    ChaCha20Rng::from_seed(seed)
}

fn rand_bytes<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut b = [0u8; N];
    rng.fill_bytes(&mut b);
    b
}

fn rand_vec(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

fn b64(x: &[u8]) -> String {
    STANDARD_NO_PAD.encode(x)
}

fn stanza(args: &[&str], body: Vec<u8>) -> Stanza {
    Stanza {
        args: args.iter().map(|s| (*s).to_string()).collect(),
        body,
    }
}

fn unknown_stanza(rng: &mut ChaCha20Rng) -> Stanza {
    let body = rand_vec(rng, 20);
    stanza(&["x-unknown-type", "arg1", "arg2"], body)
}

/// Deterministic `mlkem1024p384` stanza.
fn mlkem_stanza(rng: &mut ChaCha20Rng, r: &Recipient, fk: &[u8; 32]) -> Stanza {
    loop {
        let rnd: [u8; kem::RANDOMNESS_LEN] = rand_bytes(rng);
        if let Ok((ss, enc)) = kem::encapsulate_deterministic(r.as_bytes(), &rnd) {
            let (enc, body) =
                hpke::seal_with_shared_secret(&*ss, enc, hpke::INFO, b"", fk).expect("seal");
            return Stanza {
                args: vec![TYPE_MLKEM.to_string(), b64(&enc)],
                body,
            };
        }
    }
}

const LOW_ARGON: ArgonParams = ArgonParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

fn argon_stanza(rng: &mut ChaCha20Rng, pw: &str, fk: &[u8; 32], params: ArgonParams) -> Stanza {
    let salt: [u8; 16] = rand_bytes(rng);
    argon::wrap_with(pw.as_bytes(), fk, &salt, params).expect("argon wrap")
}

/// Serialize stanzas and the `---` prefix without enforcing parser limits.
fn raw_prefix(stanzas: &[Stanza]) -> Vec<u8> {
    let mut out = b"secreto/v1\n".to_vec();
    for s in stanzas {
        out.extend_from_slice(format!("-> {}\n", s.args.join(" ")).as_bytes());
        let b = b64(&s.body);
        let mut rest = b.as_bytes();
        while rest.len() >= 64 {
            out.extend_from_slice(&rest[..64]);
            out.push(b'\n');
            rest = &rest[64..];
        }
        out.extend_from_slice(rest);
        out.push(b'\n');
    }
    out.extend_from_slice(b"---");
    out
}

fn finish_header(prefix: &[u8], mac: &[u8; 64]) -> Vec<u8> {
    let mut h = prefix.to_vec();
    h.push(b' ');
    h.extend_from_slice(b64(mac).as_bytes());
    h.push(b'\n');
    h
}

/// A fully assembled file broken into its parts, so tests can tamper.
struct Built {
    fk: [u8; 32],
    nonce: [u8; 16],
    header: Vec<u8>,
    inner: Vec<u8>,
    payload: Vec<u8>,
}

impl Built {
    fn file(&self) -> Vec<u8> {
        let mut f = self.header.clone();
        f.extend_from_slice(&self.payload);
        f
    }
}

fn assemble(
    fk: [u8; 32],
    stanzas: &[Stanza],
    nonce: [u8; 16],
    mk_inner: impl FnOnce(&[u8; 64]) -> Vec<u8>,
) -> Built {
    let prefix = raw_prefix(stanzas);
    let mac = header::compute_mac(&fk, &prefix);
    let header = finish_header(&prefix, &mac);
    let inner = mk_inner(&mac);
    let payload = stream::encrypt(&fk, &nonce, &inner).expect("stream");
    Built {
        fk,
        nonce,
        header,
        inner,
        payload,
    }
}

/// Encrypt arbitrary chunks with explicit final flags.
fn chunk_payload(fk: &[u8; 32], nonce: &[u8; 16], chunks: &[(&[u8], bool)]) -> Vec<u8> {
    let key = stream::payload_key(fk, nonce);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let mut out = nonce.to_vec();
    for (i, (pt, last)) in chunks.iter().enumerate() {
        let n = stream::chunk_nonce(i as u128, *last).expect("nonce");
        out.extend_from_slice(&cipher.encrypt((&n).into(), *pt).expect("aead"));
    }
    out
}

fn plain_inner(content: &[u8]) -> Vec<u8> {
    inner::build(content, None, false).to_vec()
}

fn signed_inner(sk: &SigningKey, mac: &[u8; 64], content: &[u8], pad: bool) -> Vec<u8> {
    let sb = sk
        .sign_deterministic(&signature_message(mac, content))
        .expect("sign");
    inner::build(content, Some(&sb), pad).to_vec()
}

fn with_header_and_payload(b: &Built, payload: Vec<u8>) -> Vec<u8> {
    let mut f = b.header.clone();
    f.extend_from_slice(&payload);
    f
}

// ---------------------------------------------------------------------------
// The vector set
// ---------------------------------------------------------------------------

struct Keys {
    rcpts: Vec<Recipient>,
    id_str: Vec<String>,
    s1: SigningKey,
    s2: SigningKey,
    s1_pub: String,
    s2_pub: String,
}

fn make_keys() -> Keys {
    let mut rcpts = Vec::new();
    let mut id_str = Vec::new();
    for label in ["A", "B", "C"] {
        let mut r = rng_for(&format!("key/identity/{label}"));
        let id = Identity::from_seed(rand_bytes(&mut r));
        rcpts.push(id.recipient().expect("recipient"));
        id_str.push(id.to_bech32().to_string());
    }
    let sk = |label: &str| {
        let mut r = rng_for(&format!("key/signing/{label}"));
        SigningKey::from_bytes(&rand_bytes::<64>(&mut r)).expect("signing key")
    };
    let (s1, s2) = (sk("1"), sk("2"));
    Keys {
        s1_pub: s1.public_key().to_bech32(),
        s2_pub: s2.public_key().to_bech32(),
        rcpts,
        id_str,
        s1,
        s2,
    }
}

struct Gen {
    keys: Keys,
    out: Vec<TestVec>,
}

impl Gen {
    fn add(&mut self, name: &str, meta: Meta, body: Vec<u8>) {
        assert!(
            !self.out.iter().any(|v| v.name == name),
            "duplicate vector {name}"
        );
        self.out.push(TestVec {
            name: name.to_string(),
            meta,
            body,
        });
    }

    fn id(&self, i: usize) -> &str {
        &self.keys.id_str[i]
    }

    /// Standard single-purpose file for recipients `who`.
    fn std_file(
        &self,
        name: &str,
        who: &[usize],
        content: &[u8],
        pad: bool,
        signer: Option<&SigningKey>,
    ) -> Built {
        let mut rng = rng_for(name);
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let stanzas: Vec<Stanza> = who
            .iter()
            .map(|&i| mlkem_stanza(&mut rng, &self.keys.rcpts[i], &fk))
            .collect();
        let nonce = rand_bytes(&mut rng);
        assemble(fk, &stanzas, nonce, |mac| match signer {
            Some(sk) => signed_inner(sk, mac, content, pad),
            None => inner::build(content, None, pad).to_vec(),
        })
    }

    /// File with caller-specified stanzas (deterministic file key/nonce).
    fn custom_file(
        &self,
        name: &str,
        mk_stanzas: impl FnOnce(&mut ChaCha20Rng, &[u8; 32]) -> Vec<Stanza>,
        content: &[u8],
    ) -> Built {
        let mut rng = rng_for(name);
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let stanzas = mk_stanzas(&mut rng, &fk);
        let nonce = rand_bytes(&mut rng);
        assemble(fk, &stanzas, nonce, |_| plain_inner(content))
    }
}

fn content_for(name: &str, n: usize) -> Vec<u8> {
    rand_vec(&mut rng_for(&format!("content/{name}")), n)
}

const HELLO: &[u8] = b"hello, secreto\n";

fn flip(v: &mut [u8], idx: usize) {
    v[idx] ^= 0x01;
}

fn replace_once(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let pos = hay
        .windows(from.len())
        .position(|w| w == from)
        .expect("pattern present");
    let mut out = hay[..pos].to_vec();
    out.extend_from_slice(to);
    out.extend_from_slice(&hay[pos + from.len()..]);
    out
}

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_index(c: u8) -> usize {
    B64_ALPHABET.iter().position(|&x| x == c).expect("b64 char")
}

fn generate_all() -> Vec<TestVec> {
    let mut g = Gen {
        keys: make_keys(),
        out: Vec::new(),
    };
    gen_success(&mut g);
    gen_no_match(&mut g);
    gen_header(&mut g);
    gen_argon(&mut g);
    gen_armor(&mut g);
    gen_payload(&mut g);
    gen_signature(&mut g);
    g.out
}

fn gen_success(g: &mut Gen) {
    let a = g.id(0).to_string();
    let c = g.id(2).to_string();

    let n = "success-single-recipient";
    let f = g.std_file(n, &[0], HELLO, false, None);
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(HELLO),
        f.file(),
    );

    let n = "success-empty-content";
    let f = g.std_file(n, &[0], b"", false, None);
    g.add(n, Meta::new(Expect::Success).id(&a).payload(b""), f.file());

    let n = "success-multi-recipient-first";
    let content = content_for(n, 300);
    let f = g.std_file(n, &[0, 1, 2], &content, false, None);
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(&content),
        f.file(),
    );
    // Same style, last recipient decrypts; extra non-matching identity first.
    let n = "success-multi-recipient-last";
    let content = content_for(n, 300);
    let f = g.std_file(n, &[0, 1, 2], &content, false, None);
    g.add(
        n,
        Meta::new(Expect::Success).id(&c).payload(&content),
        f.file(),
    );

    let n = "success-armored";
    let content = content_for(n, 500);
    let f = g.std_file(n, &[0], &content, false, None);
    g.add(
        n,
        Meta::new(Expect::Success)
            .id(&a)
            .payload(&content)
            .armored(),
        armor::encode(&f.file()).into_bytes(),
    );

    let n = "success-armored-surrounding-whitespace";
    let f = g.std_file(n, &[0], HELLO, false, None);
    let text = format!("\n\n  {}\n\n", armor::encode(&f.file()).trim_end());
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(HELLO).armored(),
        text.into_bytes(),
    );

    let n = "success-padded";
    let content = content_for(n, 1000);
    let f = g.std_file(n, &[0], &content, true, None);
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(&content),
        f.file(),
    );

    let n = "success-padded-small";
    let f = g.std_file(n, &[0], b"x", true, None);
    g.add(n, Meta::new(Expect::Success).id(&a).payload(b"x"), f.file());

    let n = "success-arbitrary-zero-padding";
    let mut rng = rng_for(n);
    let fk: [u8; 32] = rand_bytes(&mut rng);
    let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
    let nonce = rand_bytes(&mut rng);
    let mut inn = vec![0u8];
    inn.extend_from_slice(HELLO);
    inn.push(0x80);
    inn.extend_from_slice(&[0u8; 5]);
    let f = assemble(fk, &[st], nonce, |_| inn);
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(HELLO),
        f.file(),
    );

    let n = "success-content-ends-with-0x80-and-zeros";
    let content = [b'a', 0x80, 0, 0, 0x80, 0];
    let f = g.std_file(n, &[0], &content, true, None);
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(&content),
        f.file(),
    );

    // Chunk boundaries.
    for (n, len) in [
        ("success-chunk-exact-one-full", 65_534usize),
        ("success-chunk-one-byte-final", 65_535),
        ("success-chunk-two-full", 131_070),
    ] {
        let content = content_for(n, len);
        let f = g.std_file(n, &[0], &content, false, None);
        g.add(
            n,
            Meta::new(Expect::Success).id(&a).payload(&content),
            f.file(),
        );
    }

    let n = "success-unknown-stanza-ignored";
    let content = HELLO.to_vec();
    let f = g.custom_file(
        n,
        |rng, fk| {
            vec![
                unknown_stanza(rng),
                mlkem_stanza(rng, &g.keys.rcpts[0], fk),
                unknown_stanza(rng),
            ]
        },
        &content,
    );
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(&content),
        f.file(),
    );

    let n = "success-malformed-mlkem-skipped";
    let f = g.custom_file(
        n,
        |rng, fk| {
            let good = mlkem_stanza(rng, &g.keys.rcpts[0], fk);
            let mut bad = good.clone();
            bad.body.pop();
            vec![bad, good]
        },
        HELLO,
    );
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(HELLO),
        f.file(),
    );

    // Passphrase files use the minimum accepted cost (m = 64 MiB).
    for (n, pw, params) in [
        (
            "success-passphrase",
            "correct horse battery staple",
            LOW_ARGON,
        ),
        (
            "success-passphrase-unicode",
            "pässwörd-日本語-🔑",
            ArgonParams {
                m_kib: 65_536,
                t: 3,
                p: 4,
            },
        ),
        (
            "success-passphrase-higher-t",
            "t=4,p=2",
            ArgonParams {
                m_kib: 65_536,
                t: 4,
                p: 2,
            },
        ),
    ] {
        let content = content_for(n, 128);
        let f = g.custom_file(
            n,
            |rng, fk| vec![argon_stanza(rng, pw, fk, params)],
            &content,
        );
        g.add(
            n,
            Meta::new(Expect::Success).pass(pw).payload(&content),
            f.file(),
        );
    }

    let n = "success-passphrase-armored-padded";
    let pw = "armored passphrase";
    let mut rng = rng_for(n);
    let fk: [u8; 32] = rand_bytes(&mut rng);
    let st = argon_stanza(&mut rng, pw, &fk, LOW_ARGON);
    let nonce = rand_bytes(&mut rng);
    let content = content_for(n, 77);
    let f = assemble(fk, &[st], nonce, |_| {
        inner::build(&content, None, true).to_vec()
    });
    g.add(
        n,
        Meta::new(Expect::Success)
            .pass(pw)
            .payload(&content)
            .armored(),
        armor::encode(&f.file()).into_bytes(),
    );

    // Signed.
    let s1p = g.keys.s1_pub.clone();
    let n = "success-signed-verified";
    let content = content_for(n, 200);
    let f = g.std_file(n, &[0], &content, false, Some(&g.keys.s1));
    g.add(
        n,
        Meta::new(Expect::Success)
            .id(&a)
            .verify(&s1p)
            .payload(&content),
        f.file(),
    );

    let n = "success-signed-no-verify";
    let content = content_for(n, 200);
    let f = g.std_file(n, &[0], &content, false, Some(&g.keys.s1));
    g.add(
        n,
        Meta::new(Expect::Success).id(&a).payload(&content),
        f.file(),
    );

    let n = "success-signed-padded-verified";
    let content = content_for(n, 1500);
    let f = g.std_file(n, &[0], &content, true, Some(&g.keys.s1));
    g.add(
        n,
        Meta::new(Expect::Success)
            .id(&a)
            .verify(&s1p)
            .payload(&content),
        f.file(),
    );

    let n = "success-signed-armored-multi-recipient";
    let content = content_for(n, 64);
    let f = g.std_file(n, &[1, 2], &content, false, Some(&g.keys.s2));
    let s2p = g.keys.s2_pub.clone();
    g.add(
        n,
        Meta::new(Expect::Success)
            .id(&c)
            .verify(&s2p)
            .payload(&content)
            .armored(),
        armor::encode(&f.file()).into_bytes(),
    );

    let n = "success-signed-multichunk-verified";
    let content = content_for(n, 70_000);
    let f = g.std_file(n, &[0], &content, false, Some(&g.keys.s1));
    g.add(
        n,
        Meta::new(Expect::Success)
            .id(&a)
            .verify(&s1p)
            .payload(&content),
        f.file(),
    );
}

fn gen_no_match(g: &mut Gen) {
    let a = g.id(0).to_string();
    let c = g.id(2).to_string();

    let n = "no-match-wrong-identity";
    let f = g.std_file(n, &[0], HELLO, false, None);
    g.add(n, Meta::new(Expect::NoMatch).id(&c), f.file());

    let n = "no-match-multi-recipient-none-listed";
    let f = g.std_file(n, &[0, 1], HELLO, false, None);
    g.add(n, Meta::new(Expect::NoMatch).id(&c), f.file());

    let n = "no-match-no-credentials";
    let f = g.std_file(n, &[0], HELLO, false, None);
    g.add(n, Meta::new(Expect::NoMatch), f.file());

    let n = "no-match-passphrase-for-key-file";
    let f = g.std_file(n, &[0], HELLO, false, None);
    g.add(n, Meta::new(Expect::NoMatch).pass("whatever"), f.file());

    let n = "no-match-identity-for-passphrase-file";
    let f = g.custom_file(
        n,
        |rng, fk| vec![argon_stanza(rng, "right pass", fk, LOW_ARGON)],
        HELLO,
    );
    g.add(n, Meta::new(Expect::NoMatch).id(&a), f.file());

    let n = "no-match-wrong-passphrase";
    let f = g.custom_file(
        n,
        |rng, fk| vec![argon_stanza(rng, "right pass", fk, LOW_ARGON)],
        HELLO,
    );
    g.add(n, Meta::new(Expect::NoMatch).pass("wrong pass"), f.file());

    let n = "no-match-unknown-stanza-only";
    let f = g.custom_file(n, |rng, _| vec![unknown_stanza(rng)], HELLO);
    g.add(n, Meta::new(Expect::NoMatch).id(&a), f.file());

    let n = "no-match-tampered-hpke-body";
    let f = g.custom_file(
        n,
        |rng, fk| {
            let mut s = mlkem_stanza(rng, &g.keys.rcpts[0], fk);
            s.body[0] ^= 1;
            vec![s]
        },
        HELLO,
    );
    g.add(n, Meta::new(Expect::NoMatch).id(&a), f.file());

    let n = "no-match-tampered-enc";
    let f = g.custom_file(
        n,
        |rng, fk| {
            let mut s = mlkem_stanza(rng, &g.keys.rcpts[0], fk);
            let mut enc = STANDARD_NO_PAD.decode(&s.args[1]).unwrap();
            enc[1600] ^= 1; // inside the P-384 ephemeral point region
            s.args[1] = b64(&enc);
            vec![s]
        },
        HELLO,
    );
    g.add(n, Meta::new(Expect::NoMatch).id(&a), f.file());

    // Malformed mlkem1024p384 stanzas are treated as non-matching.
    type Mutator = Box<dyn Fn(&mut Stanza)>;
    let cases: Vec<(&str, Mutator)> = vec![
        (
            "no-match-mlkem-body-47",
            Box::new(|s: &mut Stanza| {
                s.body.pop();
            }),
        ),
        (
            "no-match-mlkem-body-49",
            Box::new(|s: &mut Stanza| s.body.push(0)),
        ),
        (
            "no-match-mlkem-body-empty",
            Box::new(|s: &mut Stanza| s.body.clear()),
        ),
        (
            "no-match-mlkem-enc-1664",
            Box::new(|s: &mut Stanza| {
                let mut e = STANDARD_NO_PAD.decode(&s.args[1]).unwrap();
                e.pop();
                s.args[1] = b64(&e);
            }),
        ),
        (
            "no-match-mlkem-enc-1666",
            Box::new(|s: &mut Stanza| {
                let mut e = STANDARD_NO_PAD.decode(&s.args[1]).unwrap();
                e.push(0);
                s.args[1] = b64(&e);
            }),
        ),
        (
            "no-match-mlkem-enc-padded-base64",
            Box::new(|s: &mut Stanza| s.args[1].push('=')),
        ),
        (
            "no-match-mlkem-enc-invalid-char",
            Box::new(|s: &mut Stanza| s.args[1].replace_range(0..1, "*")),
        ),
        (
            "no-match-mlkem-extra-argument",
            Box::new(|s: &mut Stanza| s.args.push("extra".into())),
        ),
        (
            "no-match-mlkem-missing-argument",
            Box::new(|s: &mut Stanza| {
                s.args.pop();
            }),
        ),
    ];
    for (n, m) in cases {
        let f = g.custom_file(
            n,
            |rng, fk| {
                let mut s = mlkem_stanza(rng, &g.keys.rcpts[0], fk);
                m(&mut s);
                vec![s]
            },
            HELLO,
        );
        g.add(n, Meta::new(Expect::NoMatch).id(&a), f.file());
    }
}

fn gen_header(g: &mut Gen) {
    let a = g.id(0).to_string();
    let base_name = "header-base";
    let base = g.std_file(base_name, &[0], HELLO, false, None);
    let file = base.file();
    let meta = || Meta::new(Expect::HeaderFailure).id(&a);

    // Version line.
    for (n, from, to) in [
        (
            "header-bad-version-v2",
            &b"secreto/v1\n"[..],
            &b"secreto/v2\n"[..],
        ),
        ("header-bad-version-case", b"secreto/v1\n", b"Secreto/v1\n"),
        (
            "header-bad-version-trailing-space",
            b"secreto/v1\n",
            b"secreto/v1 \n",
        ),
        (
            "header-bad-version-age",
            b"secreto/v1\n",
            b"age-encryption.org/v1\n",
        ),
    ] {
        g.add(n, meta(), replace_once(&file, from, to));
    }
    g.add("header-empty-file", meta(), Vec::new());
    g.add("header-version-only", meta(), b"secreto/v1\n".to_vec());
    g.add("header-version-without-lf", meta(), b"secreto/v1".to_vec());

    // MAC.
    let mac_start = base.header.len() - 87; // "--- " is 4 chars; 86 mac chars + LF
    let mac_line_start = base.header.len() - 4 - 86 - 1;
    let _ = mac_start;
    {
        let mut f = file.clone();
        let idx = base.header.len() - 1 - 86 + 3; // a MAC character
        let _ = idx;
        let first_mac = mac_line_start + 4;
        f[first_mac] = if f[first_mac] == b'A' { b'B' } else { b'A' };
        g.add("header-bad-mac", meta(), f);
    }
    {
        // Non-canonical base64: set trailing (unused) bits of the last char.
        let mut f = file.clone();
        let last = base.header.len() - 2;
        let idx = b64_index(f[last]);
        assert_eq!(idx & 0x0f, 0, "canonical MAC has zero trailing bits");
        f[last] = B64_ALPHABET[idx | 1];
        g.add("header-mac-noncanonical-base64", meta(), f);
    }
    {
        let mut f = file.clone();
        let last = base.header.len() - 1;
        f.insert(last, b'=');
        g.add("header-mac-padded", meta(), f);
    }
    {
        let mut f = file.clone();
        let last = base.header.len() - 1;
        f.insert(last, b'=');
        f.insert(last, b'=');
        g.add("header-mac-double-padded", meta(), f);
    }
    {
        let mut f = file.clone();
        f.remove(base.header.len() - 2);
        g.add("header-mac-short", meta(), f);
    }
    {
        let mut f = file.clone();
        let last = base.header.len() - 1;
        f.insert(last, b'A');
        g.add("header-mac-long", meta(), f);
    }
    {
        let mut f = file.clone();
        let p = base.header.len() - 5;
        f[p] = b'*';
        g.add("header-mac-invalid-char", meta(), f);
    }
    {
        let mut f = file.clone();
        f[mac_line_start + 3] = b'\t'; // "---\t<mac>"
        g.add("header-mac-line-bad-separator", meta(), f);
    }
    g.add(
        "header-truncated-mid-mac",
        meta(),
        file[..base.header.len() - 20].to_vec(),
    );
    g.add(
        "header-truncated-before-mac-line",
        meta(),
        file[..mac_line_start].to_vec(),
    );
    g.add("header-truncated-mid-stanza", meta(), file[..200].to_vec());
    g.add(
        "header-truncated-no-final-lf",
        meta(),
        file[..base.header.len() - 1].to_vec(),
    );

    // MAC computed with the wrong key.
    {
        let mut rng = rng_for("header-mac-wrong-key");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let other: [u8; 32] = rand_bytes(&mut rng);
        let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let prefix = raw_prefix(&[st]);
        let mac = header::compute_mac(&other, &prefix);
        let hdr = finish_header(&prefix, &mac);
        let payload = stream::encrypt(&fk, &rand_bytes(&mut rng), &plain_inner(HELLO)).unwrap();
        let mut f = hdr;
        f.extend_from_slice(&payload);
        g.add("header-mac-wrong-key", meta(), f);
    }

    // Header modified after MAC computation.
    {
        let mut rng = rng_for("header-modified-after-mac");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let s0 = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let unk = unknown_stanza(&mut rng);
        let b = assemble(fk, &[s0.clone(), unk.clone()], rand_bytes(&mut rng), |_| {
            plain_inner(HELLO)
        });
        let mut changed = unk;
        changed.body[0] ^= 0x01;
        let mut f = b.file();
        let old = raw_prefix(&[s0.clone(), changed.clone()]);
        f[..old.len()].copy_from_slice(&old);
        g.add("header-modified-after-mac-unknown-body", meta(), f);

        let mut changed = stanza(&["x-unknown-type", "arg1", "arg2"], Vec::new());
        changed.body = {
            // same length, different content in an *argument*
            vec![]
        };
        let _ = changed;
        let b2 = assemble(
            fk,
            &[s0.clone(), stanza(&["x", "a"], vec![1, 2, 3])],
            rand_bytes(&mut rng),
            |_| plain_inner(HELLO),
        );
        let f2 = replace_once(&b2.file(), b"-> x a\n", b"-> x b\n");
        g.add("header-modified-after-mac-unknown-arg", meta(), f2);
    }

    // Stanza syntax.
    let mk = |name: &str, f: &mut dyn FnMut(&Built) -> Vec<u8>| -> (String, Vec<u8>) {
        let b = g.std_file(name, &[0], HELLO, false, None);
        (name.to_string(), f(&b))
    };
    let _ = mk;

    {
        // Final body line exactly 64 chars and no short terminator line.
        let b = assemble(
            [7u8; 32],
            &[stanza(&["x-unknown-type"], vec![9u8; 48]), {
                let mut rng = rng_for("header-missing-final-line");
                mlkem_stanza(&mut rng, &g.keys.rcpts[0], &[7u8; 32])
            }],
            [3u8; 16],
            |_| plain_inner(HELLO),
        );
        // Remove the empty terminating line after the 64-char body of the
        // 48-byte unknown stanza: body line is followed directly by "->".
        let full = b.file();
        let b64body = b64(&[9u8; 48]);
        let needle = format!("{b64body}\n\n");
        let f = replace_once(&full, needle.as_bytes(), format!("{b64body}\n").as_bytes());
        g.add("header-missing-final-body-line", meta(), f);
    }
    {
        let mut rng = rng_for("header-body-line-65");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let s0 = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let b = assemble(
            fk,
            &[stanza(&["x-unknown-type"], vec![5u8; 60]), s0],
            rand_bytes(&mut rng),
            |_| plain_inner(HELLO),
        );
        // 60 bytes -> 80 chars -> a 64-char line plus 16-char line; make
        // the first line 65 chars by moving one char over.
        let body = b64(&[5u8; 60]);
        let (l1, l2) = body.split_at(64);
        let old = format!("{l1}\n{l2}\n");
        let new = format!("{l1}{}\n{}\n", &l2[..1], &l2[1..]);
        let f = replace_once(&b.file(), old.as_bytes(), new.as_bytes());
        g.add("header-body-line-too-long-65", meta(), f);
    }
    {
        // Non-canonical base64 in a stanza body (trailing bits set).
        let mut rng = rng_for("header-body-noncanonical-base64");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let s0 = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        // 1-byte body encodes to 2 chars with 4 spare bits.
        let b = assemble(
            fk,
            &[stanza(&["x-unknown-type"], vec![0u8]), s0],
            rand_bytes(&mut rng),
            |_| plain_inner(HELLO),
        );
        let f = replace_once(
            &b.file(),
            b"-> x-unknown-type\nAA\n",
            b"-> x-unknown-type\nAB\n",
        );
        g.add("header-body-noncanonical-base64", meta(), f);
        let f = replace_once(
            &b.file(),
            b"-> x-unknown-type\nAA\n",
            b"-> x-unknown-type\nAA==\n",
        );
        g.add("header-body-padded-base64", meta(), f);
        let f = replace_once(
            &b.file(),
            b"-> x-unknown-type\nAA\n",
            b"-> x-unknown-type\nA\n",
        );
        g.add("header-body-invalid-base64-length", meta(), f);
        let f = replace_once(
            &b.file(),
            b"-> x-unknown-type\nAA\n",
            b"-> x-unknown-type\nA*\n",
        );
        g.add("header-body-invalid-base64-char", meta(), f);
    }
    {
        let b = g.std_file("header-stanza-no-space", &[0], HELLO, false, None);
        let f = replace_once(&b.file(), b"-> mlkem1024p384 ", b"->mlkem1024p384 ");
        g.add("header-stanza-missing-space-after-arrow", meta(), f);
        let f = replace_once(&b.file(), b"-> mlkem1024p384 ", b"-> mlkem1024p384  ");
        g.add("header-stanza-double-space", meta(), f);
        let f = replace_once(&b.file(), b"-> mlkem1024p384 ", b"-> \n-> mlkem1024p384 ");
        g.add("header-stanza-arg-missing-type", meta(), f);
        let f = replace_once(&b.file(), b"-> mlkem1024p384 ", b"-- mlkem1024p384 ");
        g.add("header-stanza-bad-prefix", meta(), f);
        let f = replace_once(&b.file(), b"-> mlkem1024p384 ", b"-> mlkem1024p384 \t");
        g.add("header-stanza-tab-in-args", meta(), f);
        let mut f = b.file();
        f.splice(11..11, b"\n".iter().copied());
        g.add("header-blank-line-after-version", meta(), f);
        let f = replace_once(&b.file(), b"\n---", b"\r\n---");
        g.add("header-crlf-line-ending", meta(), f);
    }
    {
        // Line longer than 4096 bytes.
        let mut rng = rng_for("header-line-too-long");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let s0 = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let long_arg = "a".repeat(4100);
        let b = assemble(
            fk,
            &[s0.clone(), stanza(&["x-unknown-type", &long_arg], vec![])],
            rand_bytes(&mut rng),
            |_| plain_inner(HELLO),
        );
        g.add("header-line-too-long", meta(), b.file());
        // Just-allowed (4096 chars incl. "-> x ") must succeed.
        let ok_arg = "a".repeat(4096 - 5);
        let b = assemble(
            fk,
            &[s0, stanza(&["x", &ok_arg], vec![])],
            rand_bytes(&mut rng),
            |_| plain_inner(HELLO),
        );
        g.add(
            "success-header-line-at-limit-4096",
            Meta::new(Expect::Success).id(&a).payload(HELLO),
            b.file(),
        );
    }
    {
        // Stanza count limits.
        let mut rng = rng_for("header-stanza-count");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let real = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let filler = |i: usize| stanza(&["x", &i.to_string()], vec![]);
        let mut st: Vec<Stanza> = (0..255).map(filler).collect();
        st.push(real.clone());
        let b = assemble(fk, &st, rand_bytes(&mut rng), |_| plain_inner(HELLO));
        g.add(
            "success-stanza-count-256",
            Meta::new(Expect::Success).id(&a).payload(HELLO),
            b.file(),
        );
        let mut st: Vec<Stanza> = (0..256).map(filler).collect();
        st.push(real);
        let b = assemble(fk, &st, rand_bytes(&mut rng), |_| plain_inner(HELLO));
        g.add("header-too-many-stanzas-257", meta(), b.file());
    }
    {
        // Header over 1 MiB.
        let mut rng = rng_for("header-too-large");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let real = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let big = stanza(&["x-unknown-type"], rand_vec(&mut rng, 790_000));
        let b = assemble(fk, &[real, big], rand_bytes(&mut rng), |_| {
            plain_inner(HELLO)
        });
        assert!(b.header.len() > (1 << 20));
        g.add("header-too-large", meta(), b.file());
    }
    {
        // Header without any stanza.
        let fk = [1u8; 32];
        let b = assemble(fk, &[], [2u8; 16], |_| plain_inner(HELLO));
        g.add("header-no-stanzas", meta(), b.file());
    }
    {
        // Non-header garbage.
        g.add("header-garbage", meta(), content_for("header-garbage", 300));
        let mut f = file.clone();
        f.splice(0..0, b"\n".iter().copied());
        g.add("header-leading-newline", meta(), f);
    }
}

fn gen_argon(g: &mut Gen) {
    let pw = "hunter2-argon";
    let meta = || Meta::new(Expect::HeaderFailure).pass(pw);

    // Mixing rule.
    let n = "argon-mixed-with-mlkem";
    let f = g.custom_file(
        n,
        |rng, fk| {
            vec![
                argon_stanza(rng, pw, fk, LOW_ARGON),
                mlkem_stanza(rng, &g.keys.rcpts[0], fk),
            ]
        },
        HELLO,
    );
    let a = g.id(0).to_string();
    g.add(n, meta().id(&a), f.file());

    let n = "argon-mixed-mlkem-first";
    let f = g.custom_file(
        n,
        |rng, fk| {
            vec![
                mlkem_stanza(rng, &g.keys.rcpts[0], fk),
                argon_stanza(rng, pw, fk, LOW_ARGON),
            ]
        },
        HELLO,
    );
    g.add(n, meta().id(&a), f.file());

    let n = "argon-mixed-with-unknown";
    let f = g.custom_file(
        n,
        |rng, fk| vec![argon_stanza(rng, pw, fk, LOW_ARGON), unknown_stanza(rng)],
        HELLO,
    );
    g.add(n, meta(), f.file());

    let n = "argon-two-argon-stanzas";
    let f = g.custom_file(
        n,
        |rng, fk| {
            vec![
                argon_stanza(rng, pw, fk, LOW_ARGON),
                argon_stanza(rng, pw, fk, LOW_ARGON),
            ]
        },
        HELLO,
    );
    g.add(n, meta(), f.file());

    // Malformed single argon2id stanzas (all rejected before Argon2 runs).
    type Mut = Box<dyn Fn(&mut Stanza)>;
    let set = |i: usize, v: &'static str| -> Mut {
        Box::new(move |s: &mut Stanza| s.args[i] = v.to_string())
    };
    let cases: Vec<(&str, Mut)> = vec![
        ("argon-m-too-small-65535", set(2, "65535")),
        ("argon-m-zero", set(2, "0")),
        ("argon-m-too-large-4194305", set(2, "4194305")),
        ("argon-m-overflow-u64", set(2, "99999999999999999999")),
        ("argon-m-leading-zero", set(2, "065536")),
        ("argon-m-plus-sign", set(2, "+65536")),
        ("argon-m-hex", set(2, "0x10000")),
        ("argon-m-empty", set(2, "")),
        ("argon-m-decimal-point", set(2, "65536.0")),
        ("argon-t-too-small-2", set(3, "2")),
        ("argon-t-zero", set(3, "0")),
        ("argon-t-too-large-17", set(3, "17")),
        ("argon-t-leading-zero", set(3, "03")),
        ("argon-t-non-numeric", set(3, "abc")),
        ("argon-p-zero", set(4, "0")),
        ("argon-p-too-large-17", set(4, "17")),
        ("argon-p-leading-zero", set(4, "01")),
        ("argon-p-negative", set(4, "-1")),
        (
            "argon-extra-argument",
            Box::new(|s: &mut Stanza| s.args.push("1".into())),
        ),
        (
            "argon-missing-argument",
            Box::new(|s: &mut Stanza| {
                s.args.pop();
            }),
        ),
        (
            "argon-body-47",
            Box::new(|s: &mut Stanza| {
                s.body.pop();
            }),
        ),
        ("argon-body-49", Box::new(|s: &mut Stanza| s.body.push(0))),
        (
            "argon-body-empty",
            Box::new(|s: &mut Stanza| s.body.clear()),
        ),
        (
            "argon-salt-15-bytes",
            Box::new(|s: &mut Stanza| {
                let mut x = STANDARD_NO_PAD.decode(&s.args[1]).unwrap();
                x.pop();
                s.args[1] = b64(&x);
            }),
        ),
        (
            "argon-salt-17-bytes",
            Box::new(|s: &mut Stanza| {
                let mut x = STANDARD_NO_PAD.decode(&s.args[1]).unwrap();
                x.push(0);
                s.args[1] = b64(&x);
            }),
        ),
        (
            "argon-salt-padded-base64",
            Box::new(|s: &mut Stanza| s.args[1].push_str("==")),
        ),
        (
            "argon-salt-noncanonical-base64",
            Box::new(|s: &mut Stanza| {
                // 16 bytes -> 22 chars; last char carries 4 spare bits.
                let last = s.args[1].pop().unwrap() as u8;
                let idx = b64_index(last);
                s.args[1].push(B64_ALPHABET[idx | 1] as char);
            }),
        ),
    ];
    for (n, m) in cases {
        let f = g.custom_file(
            n,
            |rng, fk| {
                let mut s = argon_stanza(rng, pw, fk, LOW_ARGON);
                m(&mut s);
                vec![s]
            },
            HELLO,
        );
        g.add(n, meta(), f.file());
    }

    // Stanza types are case-sensitive: `Argon2id` is an unknown type.
    let n = "no-match-argon-type-case-differs";
    let f = g.custom_file(
        n,
        |rng, fk| {
            let mut s = argon_stanza(rng, pw, fk, LOW_ARGON);
            s.args[0] = "Argon2id".to_string();
            vec![s]
        },
        HELLO,
    );
    // Unknown type with the same shape: ignored, hence no match.
    g.add(n, Meta::new(Expect::NoMatch).pass(pw), f.file());
}

fn gen_armor(g: &mut Gen) {
    let a = g.id(0).to_string();
    // Pick a content length so the armored base64 ends with padding.
    let mut len = 40usize;
    let (base, armored) = loop {
        let content = content_for("armor-base", len);
        let b = g.std_file("armor-base", &[0], &content, false, None);
        let text = armor::encode(&b.file());
        let last_body = text.lines().rev().nth(1).unwrap().to_string();
        if last_body.ends_with('=') {
            break (b, text);
        }
        len += 1;
    };
    let _ = base;
    let meta = || Meta::new(Expect::HeaderFailure).id(&a).armored();
    let lines: Vec<&str> = armored.lines().collect();
    let begin = lines[0];
    let end = *lines.last().unwrap();
    let body: Vec<&str> = lines[1..lines.len() - 1].to_vec();
    let join = |b: &[String]| -> String {
        let mut s = format!("{begin}\n");
        for l in b {
            s.push_str(l);
            s.push('\n');
        }
        s.push_str(end);
        s.push('\n');
        s
    };
    let owned: Vec<String> = body.iter().map(|s| s.to_string()).collect();

    g.add(
        "armor-wrong-label",
        meta(),
        armored
            .replace("SECRETO ENCRYPTED FILE", "SECRETO ENCRYPTED FIL")
            .into_bytes(),
    );
    g.add(
        "armor-label-mismatch-begin-end",
        meta(),
        armored
            .replacen("END SECRETO ENCRYPTED FILE", "END SECRETO FILE", 1)
            .into_bytes(),
    );
    g.add(
        "armor-lowercase-begin",
        meta(),
        armored.replacen("BEGIN", "begin", 1).into_bytes(),
    );
    g.add(
        "armor-missing-end",
        meta(),
        format!("{}\n", lines[..lines.len() - 1].join("\n")).into_bytes(),
    );
    g.add(
        "armor-data-after-end",
        meta(),
        format!("{armored}extra\n").into_bytes(),
    );
    g.add(
        "armor-second-block-after-end",
        meta(),
        format!("{armored}{armored}").into_bytes(),
    );
    g.add(
        "armor-data-before-begin",
        meta(),
        format!("junk\n{armored}").into_bytes(),
    );
    {
        // Re-wrap at 60 columns.
        let joined: String = owned.concat();
        let rewrapped: Vec<String> = joined
            .as_bytes()
            .chunks(60)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        g.add("armor-line-width-60", meta(), join(&rewrapped).into_bytes());
        let rewrapped: Vec<String> = joined
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        g.add("armor-line-width-76", meta(), join(&rewrapped).into_bytes());
    }
    {
        let mut b = owned.clone();
        b.insert(1, String::new());
        g.add("armor-blank-line-inside", meta(), join(&b).into_bytes());
        let mut b = owned.clone();
        b.push(String::new());
        g.add(
            "armor-trailing-blank-body-line",
            meta(),
            join(&b).into_bytes(),
        );
        let mut b = owned.clone();
        b[0].insert(10, ' ');
        g.add("armor-space-inside-line", meta(), join(&b).into_bytes());
        let mut b = owned.clone();
        let l = b[0].len();
        b[0].replace_range(l - 1..l, "*");
        g.add("armor-invalid-char", meta(), join(&b).into_bytes());
        let mut b = owned.clone();
        b.insert(0, "Version: 1".into());
        g.add("armor-header-line", meta(), join(&b).into_bytes());
        g.add(
            "armor-empty-body",
            meta(),
            format!("{begin}\n{end}\n").into_bytes(),
        );
    }
    {
        // Non-canonical trailing bits in the final base64 group.
        let mut b = owned.clone();
        let last = b.last_mut().unwrap();
        let pads = last.chars().rev().take_while(|&c| c == '=').count();
        assert!(pads >= 1);
        let pos = last.len() - pads - 1;
        let idx = b64_index(last.as_bytes()[pos]);
        assert_eq!(idx & 1, 0);
        last.replace_range(pos..pos + 1, &(B64_ALPHABET[idx | 1] as char).to_string());
        g.add(
            "armor-noncanonical-trailing-bits",
            meta(),
            join(&b).into_bytes(),
        );

        // Padding stripped.
        let mut b = owned.clone();
        let last = b.last_mut().unwrap();
        *last = last.trim_end_matches('=').to_string();
        g.add("armor-missing-padding", meta(), join(&b).into_bytes());

        // Extra padding.
        let mut b = owned.clone();
        b.last_mut().unwrap().push('=');
        g.add("armor-extra-padding", meta(), join(&b).into_bytes());
    }
    {
        // URL-safe alphabet.
        let b: Vec<String> = owned
            .iter()
            .map(|l| l.replace('+', "-").replace('/', "_"))
            .collect();
        if b != owned {
            g.add("armor-urlsafe-alphabet", meta(), join(&b).into_bytes());
        }
    }
    // Valid armor around a corrupted binary file: failure comes from the
    // header, not the armor layer.
    {
        let mut rng = rng_for("armor-bad-version");
        let fk: [u8; 32] = rand_bytes(&mut rng);
        let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
        let b = assemble(fk, &[st], rand_bytes(&mut rng), |_| plain_inner(HELLO));
        let f = replace_once(&b.file(), b"secreto/v1\n", b"secreto/v9\n");
        g.add(
            "armor-valid-wrapping-bad-version",
            meta(),
            armor::encode(&f).into_bytes(),
        );
    }
    // Armored payload failure: truncated payload inside valid armor.
    {
        let b = g.std_file("armor-payload-truncated", &[0], HELLO, false, None);
        let mut f = b.file();
        f.pop();
        g.add(
            "armor-valid-wrapping-truncated-payload",
            Meta::new(Expect::PayloadFailure).id(&a).armored(),
            armor::encode(&f).into_bytes(),
        );
    }
}

fn gen_payload(g: &mut Gen) {
    let a = g.id(0).to_string();
    let meta = || Meta::new(Expect::PayloadFailure).id(&a);

    let multi = content_for("payload-multichunk", 65_535); // inner = 65537 -> 2 chunks
    let base = g.std_file("payload-multi-base", &[0], &multi, false, None);
    assert_eq!(base.inner.len(), 65_537);
    let file = base.file();
    let full_chunk = 65_536 + 16;

    // Truncations.
    g.add(
        "payload-truncated-last-byte",
        meta(),
        file[..file.len() - 1].to_vec(),
    );
    g.add(
        "payload-truncated-in-tag",
        meta(),
        file[..file.len() - 10].to_vec(),
    );
    g.add(
        "payload-truncated-final-chunk-removed",
        meta(),
        file[..base.header.len() + 16 + full_chunk].to_vec(),
    );
    g.add(
        "payload-truncated-mid-first-chunk",
        meta(),
        file[..base.header.len() + 16 + 1000].to_vec(),
    );
    g.add("payload-truncated-no-payload", meta(), base.header.clone());
    g.add(
        "payload-truncated-partial-nonce",
        meta(),
        file[..base.header.len() + 8].to_vec(),
    );
    g.add(
        "payload-truncated-nonce-only",
        meta(),
        file[..base.header.len() + 16].to_vec(),
    );
    g.add(
        "payload-truncated-nonce-and-partial-tag",
        meta(),
        file[..base.header.len() + 16 + 15].to_vec(),
    );
    {
        let mut f = file.clone();
        f.push(0);
        g.add("payload-trailing-byte", meta(), f);
        let mut f = file.clone();
        f.extend_from_slice(&[0u8; 16]);
        g.add("payload-trailing-16-zeros", meta(), f);
        let mut f = file.clone();
        f.extend_from_slice(&file[base.header.len() + 16..base.header.len() + 16 + full_chunk]);
        g.add("payload-trailing-extra-chunk", meta(), f);
    }

    // Single-chunk truncation / corruption.
    {
        let b = g.std_file("payload-small-base", &[0], HELLO, false, None);
        let f = b.file();
        g.add(
            "payload-small-truncated-last-byte",
            meta(),
            f[..f.len() - 1].to_vec(),
        );
        let mut x = f.clone();
        let p = b.header.len() + 16;
        flip(&mut x, p);
        g.add("payload-small-flip-ciphertext", meta(), x);
        let mut x = f.clone();
        let p = x.len() - 1;
        flip(&mut x, p);
        g.add("payload-small-flip-tag", meta(), x);
        let mut x = f.clone();
        let p = b.header.len();
        flip(&mut x, p);
        g.add("payload-small-flip-nonce", meta(), x);
    }
    {
        let mut x = file.clone();
        let p = base.header.len() + 16 + 100;
        flip(&mut x, p);
        g.add("payload-flip-first-chunk", meta(), x);
        let mut x = file.clone();
        let p = x.len() - 1;
        flip(&mut x, p);
        g.add("payload-flip-last-chunk-tag", meta(), x);
    }
    // Payload encrypted under a different file key.
    {
        let other = [0x55u8; 32];
        let payload = stream::encrypt(&other, &base.nonce, &base.inner).unwrap();
        g.add(
            "payload-wrong-file-key",
            meta(),
            with_header_and_payload(&base, payload),
        );
    }
    // Chunk reordering.
    {
        let mut inn = vec![0u8; 0];
        inn.extend_from_slice(&base.inner);
        let c0 = &inn[..65_536];
        let c1 = &inn[65_536..];
        // swap ciphertext chunks (second chunk is short, so cannot swap
        // blindly): use a three-chunk file.
        let content = content_for("payload-three-chunks", 131_072 + 10);
        let b3 = g.std_file("payload-three-base", &[0], &content, false, None);
        let ct = &b3.payload[16..];
        let n = 65_536 + 16;
        let (x0, x1, x2) = (&ct[..n], &ct[n..2 * n], &ct[2 * n..]);
        let mut p = b3.nonce.to_vec();
        p.extend_from_slice(x1);
        p.extend_from_slice(x0);
        p.extend_from_slice(x2);
        g.add(
            "payload-chunks-swapped",
            meta(),
            with_header_and_payload(&b3, p),
        );
        let mut p = b3.nonce.to_vec();
        p.extend_from_slice(x0);
        p.extend_from_slice(x0);
        p.extend_from_slice(x2);
        g.add(
            "payload-chunk-duplicated",
            meta(),
            with_header_and_payload(&b3, p),
        );
        let mut p = b3.nonce.to_vec();
        p.extend_from_slice(x0);
        p.extend_from_slice(x2);
        g.add(
            "payload-chunk-dropped-middle",
            meta(),
            with_header_and_payload(&b3, p),
        );
        let _ = (c0, c1);
    }

    // STREAM flag handling.
    {
        let inn = plain_inner(HELLO);
        let p = chunk_payload(&base.fk, &base.nonce, &[(&inn, false)]);
        let small = g.std_file("payload-flag-small", &[0], HELLO, false, None);
        g.add(
            "payload-flag-single-chunk-not-final",
            meta(),
            with_header_and_payload(
                &small,
                chunk_payload(&small.fk, &small.nonce, &[(&inn, false)]),
            ),
        );
        let _ = p;

        let c0 = &base.inner[..65_536];
        let c1 = &base.inner[65_536..];
        g.add(
            "payload-flag-last-chunk-not-final",
            meta(),
            with_header_and_payload(
                &base,
                chunk_payload(&base.fk, &base.nonce, &[(c0, false), (c1, false)]),
            ),
        );
        g.add(
            "payload-flag-first-chunk-marked-final",
            meta(),
            with_header_and_payload(
                &base,
                chunk_payload(&base.fk, &base.nonce, &[(c0, true), (c1, true)]),
            ),
        );
        g.add(
            "payload-flag-stream-ends-after-first-chunk",
            meta(),
            with_header_and_payload(&base, chunk_payload(&base.fk, &base.nonce, &[(c0, true)])),
        );
        // Exactly one full chunk followed by an empty final chunk.
        let content = content_for("payload-empty-final", 65_534);
        let b = g.std_file("payload-empty-final-base", &[0], &content, false, None);
        assert_eq!(b.inner.len(), 65_536);
        g.add(
            "payload-empty-final-chunk",
            meta(),
            with_header_and_payload(
                &b,
                chunk_payload(&b.fk, &b.nonce, &[(&b.inner, false), (b"", true)]),
            ),
        );
        g.add(
            "payload-full-chunk-not-final-no-more",
            meta(),
            with_header_and_payload(&b, chunk_payload(&b.fk, &b.nonce, &[(&b.inner, false)])),
        );
        // Stream with a zero-length plaintext.
        g.add(
            "payload-empty-stream-plaintext",
            meta(),
            with_header_and_payload(
                &small,
                chunk_payload(&small.fk, &small.nonce, &[(b"", true)]),
            ),
        );
        // Counter does not start at zero: encrypt the chunk as index 1.
        let key = stream::payload_key(&small.fk, &small.nonce);
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let nonce1 = stream::chunk_nonce(1, true).unwrap();
        let mut p = small.nonce.to_vec();
        p.extend_from_slice(&cipher.encrypt((&nonce1).into(), inn.as_slice()).unwrap());
        g.add(
            "payload-counter-starts-at-one",
            meta(),
            with_header_and_payload(&small, p),
        );
    }

    // Inner plaintext structure (all within a correctly authenticated STREAM).
    {
        let small = |name: &str, g: &Gen| g.std_file(name, &[0], HELLO, false, None);
        let mk = |g: &mut Gen, name: &str, inn: Vec<u8>, meta: Meta| {
            let b = small(name, g);
            let p = stream::encrypt(&b.fk, &b.nonce, &inn).unwrap();
            let f = with_header_and_payload(&b, p);
            g.add(name, meta, f);
        };
        let body = |flags: u8, tail: &[u8]| {
            let mut v = vec![flags];
            v.extend_from_slice(HELLO);
            v.extend_from_slice(tail);
            v
        };
        mk(g, "inner-unknown-flags-0x02", body(0x02, &[0x80]), meta());
        mk(g, "inner-unknown-flags-0x80", body(0x80, &[0x80]), meta());
        mk(g, "inner-unknown-flags-0xff", body(0xff, &[0x80]), meta());
        mk(g, "inner-unknown-flags-0x03", body(0x03, &[0x80]), meta());
        mk(
            g,
            "inner-flags-signed-but-no-sigblock",
            body(0x01, &[0x80]),
            meta(),
        );
        mk(
            g,
            "inner-flags-signed-truncated-sigblock",
            body(0x01, &[&[0x80][..], &vec![0u8; 4700]].concat()),
            meta(),
        );
        mk(g, "inner-missing-terminator", body(0x00, &[]), meta());
        mk(
            g,
            "inner-missing-terminator-zeros",
            body(0x00, &[0, 0, 0]),
            meta(),
        );
        mk(
            g,
            "inner-wrong-terminator-0x81",
            body(0x00, &[0x81]),
            meta(),
        );
        mk(
            g,
            "inner-wrong-terminator-0x01",
            body(0x00, &[0x01, 0x00]),
            meta(),
        );
        mk(
            g,
            "inner-nonzero-after-terminator",
            body(0x00, &[0x80, 0x00, 0x01]),
            meta(),
        );
        mk(
            g,
            "inner-terminator-then-0x80",
            body(0x00, &[0x80, 0x00, 0x80, 0x01]),
            meta(),
        );
        mk(g, "inner-only-flags", vec![0x00], meta());
        mk(g, "inner-flags-and-zero", vec![0x00, 0x00], meta());
        mk(g, "inner-all-zero", vec![0u8; 40], meta());
        mk(
            g,
            "inner-unsigned-flag-with-sigblock-appended",
            body(0x00, &[&[0x80][..], &vec![0x33u8; 4723]].concat()),
            meta(),
        );
        // Signed flag but padding invalid before the sigblock.
        mk(
            g,
            "inner-signed-missing-terminator",
            body(0x01, &vec![0x33u8; 4723]),
            meta(),
        );
        mk(
            g,
            "inner-signed-zero-sigblock-no-terminator",
            body(0x01, &vec![0u8; 4723]),
            meta(),
        );
        // Padding zeros placed after the sigblock instead of before it.
        let b = g.std_file(
            "inner-signed-padding-after-sigblock",
            &[0],
            HELLO,
            false,
            Some(&g.keys.s1),
        );
        let mut inn = b.inner.clone();
        inn.extend_from_slice(&[0u8; 8]);
        let p = stream::encrypt(&b.fk, &b.nonce, &inn).unwrap();
        let f = with_header_and_payload(&b, p);
        g.add("inner-signed-padding-after-sigblock", meta(), f);
    }
}

fn gen_signature(g: &mut Gen) {
    let a = g.id(0).to_string();
    let s1p = g.keys.s1_pub.clone();
    let s2p = g.keys.s2_pub.clone();
    let meta = || Meta::new(Expect::SignatureFailure).id(&a);

    let n = "sig-wrong-signer";
    let f = g.std_file(n, &[0], HELLO, false, Some(&g.keys.s1));
    g.add(n, meta().verify(&s2p), f.file());

    let n = "sig-verify-requested-but-unsigned";
    let f = g.std_file(n, &[0], HELLO, false, None);
    g.add(n, meta().verify(&s1p), f.file());

    let n = "sig-wrong-signer-armored";
    let f = g.std_file(n, &[0], HELLO, true, Some(&g.keys.s2));
    g.add(
        n,
        meta().verify(&s1p).armored(),
        armor::encode(&f.file()).into_bytes(),
    );

    // Tampered signature components, re-encrypted so the STREAM is valid.
    let sign_parts =
        |g: &Gen, name: &str, content: &[u8], edit: &dyn Fn(&mut SigBlock, &[u8; 64])| {
            let mut rng = rng_for(name);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |mac| {
                let mut sb = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, content))
                    .unwrap();
                edit(&mut sb, mac);
                inner::build(content, Some(&sb), false).to_vec()
            })
        };
    let content = content_for("sig-content", 100);
    type SigEdit = Box<dyn Fn(&mut SigBlock, &[u8; 64])>;
    let cases: Vec<(&str, SigEdit)> = vec![
        (
            "sig-bad-ed25519",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| sb.ed25519[3] ^= 1),
        ),
        (
            "sig-bad-mldsa",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| sb.mldsa[100] ^= 1),
        ),
        (
            "sig-bad-mldsa-last-byte",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| sb.mldsa[4626] ^= 1),
        ),
        (
            "sig-ed25519-zeroed",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| sb.ed25519 = [0u8; 64]),
        ),
        (
            "sig-mldsa-zeroed",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| *sb.mldsa = [0u8; 4627]),
        ),
        (
            "sig-signer-id-altered",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| sb.signer_id[0] ^= 1),
        ),
        (
            "sig-swapped-components",
            Box::new(|sb: &mut SigBlock, _: &[u8; 64]| {
                // swap the two ed25519 halves
                let (l, r) = sb.ed25519.split_at_mut(32);
                l.swap_with_slice(r);
            }),
        ),
    ];
    for (n, edit) in cases {
        let b = sign_parts(g, n, &content, &*edit);
        g.add(n, meta().verify(&s1p), b.file());
    }

    // Signature over different content.
    {
        let n = "sig-over-different-content";
        let b = {
            let mut rng = rng_for(n);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |mac| {
                let sb = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, b"other content"))
                    .unwrap();
                inner::build(&content, Some(&sb), false).to_vec()
            })
        };
        g.add(n, meta().verify(&s1p), b.file());

        // Signature bound to a different header MAC (replay into new file).
        let n = "sig-over-different-header-mac";
        let b = {
            let mut rng = rng_for(n);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |_mac| {
                signed_inner(&g.keys.s1, &[0xabu8; 64], &content, false)
            })
        };
        g.add(n, meta().verify(&s1p), b.file());

        // Same content signed with a signature that omits the length prefix
        // (message construction error).
        let n = "sig-message-without-length";
        let b = {
            let mut rng = rng_for(n);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |mac| {
                let mut m = b"secreto/v1/signature".to_vec();
                m.extend_from_slice(mac);
                m.extend_from_slice(&sha2::Sha512::digest(&content));
                let sb = g.keys.s1.sign_deterministic(&m).unwrap();
                inner::build(&content, Some(&sb), false).to_vec()
            })
        };
        g.add(n, meta().verify(&s1p), b.file());

        // Only Ed25519 valid: ML-DSA signature is for another message.
        let n = "sig-only-ed25519-valid";
        let b = {
            let mut rng = rng_for(n);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |mac| {
                let good = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, &content))
                    .unwrap();
                let bad = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, b"x"))
                    .unwrap();
                let sb = SigBlock {
                    signer_id: good.signer_id,
                    ed25519: good.ed25519,
                    mldsa: bad.mldsa,
                };
                inner::build(&content, Some(&sb), false).to_vec()
            })
        };
        g.add(n, meta().verify(&s1p), b.file());

        // Only ML-DSA valid.
        let n = "sig-only-mldsa-valid";
        let b = {
            let mut rng = rng_for(n);
            let fk: [u8; 32] = rand_bytes(&mut rng);
            let st = mlkem_stanza(&mut rng, &g.keys.rcpts[0], &fk);
            let nonce = rand_bytes(&mut rng);
            assemble(fk, &[st], nonce, |mac| {
                let good = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, &content))
                    .unwrap();
                let bad = g
                    .keys
                    .s1
                    .sign_deterministic(&signature_message(mac, b"x"))
                    .unwrap();
                let sb = SigBlock {
                    signer_id: good.signer_id,
                    ed25519: bad.ed25519,
                    mldsa: good.mldsa,
                };
                inner::build(&content, Some(&sb), false).to_vec()
            })
        };
        g.add(n, meta().verify(&s1p), b.file());
    }

    // Verification must fail the same way for padded signed files.
    let n = "sig-wrong-signer-padded";
    let f = g.std_file(n, &[0], &content, true, Some(&g.keys.s1));
    g.add(n, meta().verify(&s2p), f.file());

    // Truncated sigblock is a format error (exit 4) even with --verify.
    let n = "sig-truncated-sigblock-with-verify";
    let b = g.std_file(n, &[0], HELLO, false, Some(&g.keys.s1));
    let mut inn = b.inner.clone();
    inn.truncate(inn.len() - 1);
    let p = stream::encrypt(&b.fk, &b.nonce, &inn).unwrap();
    g.add(
        n,
        Meta::new(Expect::PayloadFailure).id(&a).verify(&s1p),
        with_header_and_payload(&b, p),
    );
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const EXT: &str = "vec";

fn write_all(dir: &Path, vectors: &[TestVec]) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // Remove stale generated files.
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().is_some_and(|x| x == EXT) {
            fs::remove_file(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    for v in vectors {
        let p = dir.join(format!("{}.{EXT}", v.name));
        fs::write(&p, v.to_bytes()).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    Ok(())
}

fn read_dir_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut m = BTreeMap::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.extension().is_some_and(|x| x == EXT) {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            m.insert(name, fs::read(&p).map_err(|e| e.to_string())?);
        }
    }
    Ok(m)
}

fn conform_all(vectors: &[TestVec]) -> Result<(), String> {
    let mut errs = Vec::new();
    for v in vectors {
        if let Err(e) = conformance(&v.name, &v.to_bytes()) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

fn cmd_generate(dir: &Path) -> Result<(), String> {
    let vectors = generate_all();
    conform_all(&vectors)?;
    write_all(dir, &vectors)?;
    println!("wrote {} vectors to {}", vectors.len(), dir.display());
    Ok(())
}

fn cmd_check(dir: &Path) -> Result<(), String> {
    let vectors = generate_all();
    conform_all(&vectors)?;
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("secreto-vectors-check-{}", std::process::id()));
    let result = (|| {
        write_all(&tmp, &vectors)?;
        let fresh = read_dir_files(&tmp)?;
        let committed = read_dir_files(dir)?;
        let mut problems = Vec::new();
        for (name, bytes) in &fresh {
            match committed.get(name) {
                None => problems.push(format!("missing: {name}")),
                Some(c) if c != bytes => problems.push(format!("differs: {name}")),
                Some(_) => {}
            }
        }
        for name in committed.keys() {
            if !fresh.contains_key(name) {
                problems.push(format!("unexpected: {name}"));
            }
        }
        // Committed files must also satisfy their own expectations.
        for (name, bytes) in &committed {
            if let Err(e) = conformance(name, bytes) {
                problems.push(e);
            }
        }
        if problems.is_empty() {
            println!("ok: {} vectors match {}", fresh.len(), dir.display());
            Ok(())
        } else {
            Err(problems.join("\n"))
        }
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match (args.get(1).map(String::as_str), args.get(2), args.len()) {
        (Some("generate"), Some(d), 3) => cmd_generate(Path::new(d)),
        (Some("check"), Some(d), 3) => cmd_check(Path::new(d)),
        _ => {
            eprintln!("usage: secreto-vectors (generate|check) <outdir>");
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("secreto-vectors: error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_prefix_matches_core_marshal() {
        let mut rng = rng_for("test");
        let st = vec![
            unknown_stanza(&mut rng),
            stanza(&["y"], vec![]),
            stanza(&["z", "a"], rand_vec(&mut rng, 200)),
        ];
        let fk = [3u8; 32];
        let (h, mac) = header::marshal(&st, &fk).unwrap();
        let prefix = raw_prefix(&st);
        assert_eq!(finish_header(&prefix, &mac), h);
    }

    #[test]
    fn generation_is_deterministic_and_conformant() {
        let a = generate_all();
        let b = generate_all();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.to_bytes(), y.to_bytes(), "{}", x.name);
        }
        conform_all(&a).unwrap();
    }
}

#[cfg(test)]
mod audit {
    use super::*;

    /// Header-failure vectors must be rejected by header parsing / unwrap /
    /// MAC, never by the payload layer.
    #[test]
    fn header_failures_fail_before_payload() {
        let mut parsed_ok = Vec::new();
        for v in generate_all() {
            if v.meta.expect != Expect::HeaderFailure {
                continue;
            }
            let body = if armor::is_armored(&v.body) {
                match armor::decode(&v.body) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            } else {
                v.body.clone()
            };
            if header::parse(&body).is_ok() {
                parsed_ok.push(v.name.clone());
            }
        }
        // Only the MAC-related vectors (and armor-wrapped bad version) parse.
        println!("{parsed_ok:?}");
        for n in &parsed_ok {
            assert!(
                n.contains("mac") || n.starts_with("argon-mixed") || n.starts_with("argon-"),
                "{n} parsed but expected header failure"
            );
        }
    }
}
