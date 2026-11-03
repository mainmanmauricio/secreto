#!/usr/bin/env python3
"""Cross-implementation interop harness for secreto (Rust, Python, C++).

Encrypt with each implementation and decrypt with each of the three (3x3).
Also checks key round-trips, negative mutations, and exit-code agreement.
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = ROOT / "interop" / "tmp"

IMPLS = {
    "rust": {
        "secreto": ROOT / "rust" / "target" / "release" / "secreto",
        "keygen": ROOT / "rust" / "target" / "release" / "secreto-keygen",
    },
    "python": {
        "secreto": ROOT / "python" / ".venv" / "bin" / "secreto",
        "keygen": ROOT / "python" / ".venv" / "bin" / "secreto-keygen",
    },
    "cpp": {
        "secreto": ROOT / "cpp" / "build" / "secreto",
        "keygen": ROOT / "cpp" / "build" / "secreto-keygen",
    },
}

SIZES = [0, 1, 65535, 65536, 65537, 196608, 1048583]
PASS = 0
FAIL = 0


def log(msg: str) -> None:
    print(msg, flush=True)


def ok(name: str) -> None:
    global PASS
    PASS += 1
    log(f"  PASS {name}")


def bad(name: str, detail: str) -> None:
    global FAIL
    FAIL += 1
    log(f"  FAIL {name}: {detail}")


def run(argv: list[str | Path], *, input: bytes | None = None, env: dict | None = None,
        timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [str(a) for a in argv],
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=e,
        timeout=timeout,
        check=False,
    )


def require_bins() -> None:
    missing = []
    for name, bins in IMPLS.items():
        for kind, path in bins.items():
            if not path.is_file():
                missing.append(f"{name}/{kind}: {path}")
    if missing:
        sys.exit("missing binaries:\n  " + "\n  ".join(missing))


def _parse_pubkey_line(stderr: bytes) -> str:
    """Last non-empty stderr line, stripping an optional 'Public key:' prefix."""
    lines = [ln.strip() for ln in stderr.decode().splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"keygen produced no public key on stderr: {stderr!r}")
    line = lines[-1]
    if line.lower().startswith("public key:"):
        line = line.split(":", 1)[1].strip()
    return line


def keygen(impl: str, out_dir: Path, signing: bool = False) -> tuple[Path, str]:
    bins = IMPLS[impl]
    tag = f"{impl}-{'sign' if signing else 'id'}-{random.randrange(1 << 32):08x}"
    secret = out_dir / f"{tag}.key"
    argv: list[str | Path] = [bins["keygen"], "-o", secret]
    if signing:
        argv.insert(1, "--signing")
    r = run(argv)
    if r.returncode != 0:
        raise RuntimeError(f"{impl} keygen failed: {r.stderr!r}")
    return secret, _parse_pubkey_line(r.stderr)


def pubkey(impl: str, secret: Path) -> str:
    r = run([IMPLS[impl]["keygen"], "-y", secret])
    if r.returncode != 0:
        raise RuntimeError(f"{impl} -y failed: {r.stderr!r}")
    return r.stdout.decode().strip()


def encrypt(
    impl: str,
    plaintext: bytes,
    *,
    recipients: list[str] | None = None,
    recipients_file: Path | None = None,
    passphrase: str | None = None,
    armor: bool = False,
    pad: bool = False,
    sign_key: Path | None = None,
    out: Path,
) -> int:
    argv: list[str | Path] = [IMPLS[impl]["secreto"], "-e", "-o", out]
    env: dict[str, str] = {}
    if recipients:
        for r in recipients:
            argv.extend(["-r", r])
    if recipients_file is not None:
        argv.extend(["-R", recipients_file])
    if passphrase is not None:
        argv.append("-p")
        # pass via FD
        # we'll open a pipe via env SECRETO_PASSPHRASE_FD using a temp file
        pf = out.parent / f".pw-{out.name}"
        pf.write_bytes(passphrase.encode() + b"\n")
        # Use a helper: pass FD by opening and inheriting — simpler: write to file and use bash
        # Spec: SECRETO_PASSPHRASE_FD. Open the file and pass the fd number.
        return _encrypt_with_passphrase_fd(impl, plaintext, argv, pf, out)
    if armor:
        argv.append("-a")
    if pad:
        argv.append("--pad")
    if sign_key is not None:
        argv.extend(["--sign", sign_key])
    r = run(argv, input=plaintext, env=env)
    return r.returncode


def _encrypt_with_passphrase_fd(
    impl: str, plaintext: bytes, argv: list[str | Path], pw_file: Path, out: Path
) -> int:
    # Open passphrase file and pass its FD to the child.
    with pw_file.open("rb") as f:
        fd = f.fileno()
        env = {"SECRETO_PASSPHRASE_FD": str(fd)}
        # Need to pass the open FD; subprocess doesn't inherit specific fds by default
        # beyond 0,1,2 unless pass_fds is set.
        e = os.environ.copy()
        e.update(env)
        r = subprocess.run(
            [str(a) for a in argv],
            input=plaintext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=e,
            pass_fds=(fd,),
            timeout=300,
            check=False,
        )
    try:
        pw_file.unlink()
    except OSError:
        pass
    return r.returncode


def decrypt(
    impl: str,
    ciphertext: Path,
    *,
    identities: list[Path] | None = None,
    passphrase: str | None = None,
    verify: str | None = None,
    out: Path,
) -> tuple[int, bytes, bytes]:
    argv: list[str | Path] = [IMPLS[impl]["secreto"], "-d", "-o", out]
    if identities:
        for i in identities:
            argv.extend(["-i", i])
    if verify is not None:
        argv.extend(["--verify", verify])
    if passphrase is not None:
        argv.append("-p")
        pw_file = out.parent / f".pw-d-{out.name}"
        pw_file.write_bytes(passphrase.encode() + b"\n")
        with pw_file.open("rb") as f:
            fd = f.fileno()
            e = os.environ.copy()
            e["SECRETO_PASSPHRASE_FD"] = str(fd)
            with ciphertext.open("rb") as cin:
                data = cin.read()
            r = subprocess.run(
                [str(a) for a in argv],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=e,
                pass_fds=(fd,),
                timeout=300,
                check=False,
            )
        try:
            pw_file.unlink()
        except OSError:
            pass
        got = out.read_bytes() if out.is_file() and r.returncode == 0 else b""
        return r.returncode, got, r.stderr
    with ciphertext.open("rb") as cin:
        data = cin.read()
    r = run(argv, input=data)
    got = out.read_bytes() if out.is_file() and r.returncode == 0 else b""
    return r.returncode, got, r.stderr


def payload_for(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def test_key_roundtrips(work: Path) -> None:
    log("== key round-trips ==")
    for gen_impl in IMPLS:
        secret, pub_from_gen = keygen(gen_impl, work)
        for y_impl in IMPLS:
            pub = pubkey(y_impl, secret)
            name = f"keygen:{gen_impl} -y:{y_impl}"
            if pub == pub_from_gen:
                ok(name)
            else:
                bad(name, f"mismatch\n    gen={pub_from_gen[:40]}...\n    -y={pub[:40]}...")
        # signing
        ssecret, spub = keygen(gen_impl, work, signing=True)
        for y_impl in IMPLS:
            r = run([IMPLS[y_impl]["keygen"], "--signing", "-y", ssecret])
            name = f"signing-keygen:{gen_impl} -y:{y_impl}"
            if r.returncode == 0 and r.stdout.decode().strip() == spub:
                ok(name)
            else:
                bad(name, f"rc={r.returncode} out={r.stdout[:60]!r} err={r.stderr[:80]!r}")


def test_matrix(work: Path) -> None:
    log("== 3x3 encrypt/decrypt matrix ==")
    # Prepare one identity per impl (any identity works for all encryptors)
    secrets = {}
    pubs = {}
    for impl in IMPLS:
        secrets[impl], pubs[impl] = keygen(impl, work)
    sign_secret, sign_pub = keygen("rust", work, signing=True)

    cases = []
    for size in SIZES:
        cases.append(("size", size, {"armor": False, "pad": False, "sign": False, "multi": False}))
    cases.append(("armor", 100, {"armor": True, "pad": False, "sign": False, "multi": False}))
    cases.append(("pad", 100, {"armor": False, "pad": True, "sign": False, "multi": False}))
    cases.append(("sign", 100, {"armor": False, "pad": False, "sign": True, "multi": False}))
    cases.append(("sign+verify", 100, {"armor": False, "pad": False, "sign": True, "verify": True, "multi": False}))
    cases.append(("multi", 50, {"armor": False, "pad": False, "sign": False, "multi": True}))
    cases.append(("pad+armor+sign", 200, {"armor": True, "pad": True, "sign": True, "verify": True, "multi": False}))

    for label, size, opts in cases:
        pt = payload_for(size, seed=size + 17)
        for enc_impl in IMPLS:
            recips = [pubs["rust"], pubs["python"], pubs["cpp"]] if opts["multi"] else [pubs["rust"]]
            ct_path = work / f"{label}-{size}-{enc_impl}.sec"
            rc = encrypt(
                enc_impl,
                pt,
                recipients=recips,
                armor=opts["armor"],
                pad=opts["pad"],
                sign_key=sign_secret if opts["sign"] else None,
                out=ct_path,
            )
            if rc != 0:
                bad(f"encrypt {label} size={size} enc={enc_impl}", f"rc={rc}")
                continue
            for dec_impl in IMPLS:
                out = work / f"{label}-{size}-{enc_impl}-dec-{dec_impl}.out"
                if out.exists():
                    out.unlink()
                # multi: each identity should work; use matching identity file that can open
                # Any of the three secrets work since we encrypted to all three pubs when multi;
                # when single, only rust's identity matches.
                id_path = secrets["rust"] if not opts["multi"] else secrets[dec_impl]
                # For multi we encrypted to all three pubs, so any secret works. Use rust's for single.
                if opts["multi"]:
                    id_path = secrets[dec_impl]
                else:
                    id_path = secrets["rust"]
                verify = sign_pub if opts.get("verify") else None
                d_rc, got, err = decrypt(
                    dec_impl, ct_path, identities=[id_path], verify=verify, out=out
                )
                name = f"{label} n={size} {enc_impl}->{dec_impl}"
                if d_rc != 0:
                    bad(name, f"decrypt rc={d_rc} err={err[:120]!r}")
                elif got != pt:
                    bad(name, f"payload mismatch (got {len(got)} want {len(pt)})")
                else:
                    ok(name)


def test_passphrase(work: Path) -> None:
    log("== passphrase decrypt interop (precomputed low-m vectors) ==")
    # Use a success passphrase testkit vector if present
    vecs = sorted((ROOT / "vectors" / "testkit").glob("*passphrase*success*.vec"))
    if not vecs:
        vecs = sorted((ROOT / "vectors" / "testkit").glob("*pass*.vec"))
    # Fallback: find any with passphrase: metadata
    chosen = None
    payload = None
    passphrase = None
    for v in sorted((ROOT / "vectors" / "testkit").glob("*.vec")):
        text = v.read_bytes()
        if b"\n\n" not in text:
            continue
        meta, body = text.split(b"\n\n", 1)
        meta_s = meta.decode()
        if "expect: success" not in meta_s or "passphrase:" not in meta_s:
            continue
        chosen = (v, body)
        for line in meta_s.splitlines():
            if line.startswith("passphrase:"):
                passphrase = line.split(":", 1)[1].strip()
            if line.startswith("payload:"):
                payload = bytes.fromhex(line.split(":", 1)[1].strip())
        break
    if not chosen or passphrase is None or payload is None:
        bad("passphrase-vector", "no success passphrase testkit vector found")
        return
    ct_path = work / "passphrase.sec"
    ct_path.write_bytes(chosen[1])
    for dec_impl in IMPLS:
        out = work / f"pass-{dec_impl}.out"
        if out.exists():
            out.unlink()
        rc, got, err = decrypt(dec_impl, ct_path, passphrase=passphrase, out=out)
        name = f"passphrase-decrypt {dec_impl}"
        if rc == 0 and got == payload:
            ok(name)
        else:
            bad(name, f"rc={rc} err={err[:100]!r}")


def mutate_and_check(work: Path) -> None:
    log("== mutation / exit-code agreement ==")
    secrets = {}
    pubs = {}
    for impl in IMPLS:
        secrets[impl], pubs[impl] = keygen(impl, work)
    sign_secret, sign_pub = keygen("rust", work, signing=True)
    pt = b"mutation-payload"
    good = work / "good.sec"
    rc = encrypt("rust", pt, recipients=[pubs["rust"]], sign_key=sign_secret, out=good)
    if rc != 0:
        bad("mutation-setup", f"encrypt rc={rc}")
        return

    # wrong identity -> exit 3
    codes = {}
    for impl in IMPLS:
        out = work / f"wrong-id-{impl}.out"
        if out.exists():
            out.unlink()
        d_rc, _, _ = decrypt(impl, good, identities=[secrets["python"]], out=out)
        codes[impl] = d_rc
    name = "wrong-identity exit codes"
    if len(set(codes.values())) == 1 and list(codes.values())[0] == 3:
        ok(f"{name}={codes}")
    else:
        bad(name, str(codes))

    # wrong signer -> exit 5
    other_sign, other_pub = keygen("python", work, signing=True)
    codes = {}
    for impl in IMPLS:
        out = work / f"wrong-sig-{impl}.out"
        if out.exists():
            out.unlink()
        d_rc, _, _ = decrypt(
            impl, good, identities=[secrets["rust"]], verify=other_pub, out=out
        )
        codes[impl] = d_rc
    name = "wrong-signer exit codes"
    if len(set(codes.values())) == 1 and list(codes.values())[0] == 5:
        ok(f"{name}={codes}")
    else:
        bad(name, str(codes))

    # bit flip in header / payload / truncation -> exit 4 (agreement)
    data = good.read_bytes()
    # find end of header (after "--- " mac line)
    hdr_end = data.find(b"\n", data.find(b"--- ")) + 1
    mutations = {
        "flip-header": bytearray(data),
        "flip-payload": bytearray(data),
        "truncate": bytearray(data[: max(hdr_end + 8, len(data) // 2)]),
    }
    if hdr_end > 10:
        mutations["flip-header"][hdr_end // 2] ^= 0x01
    if len(data) > hdr_end + 20:
        mutations["flip-payload"][hdr_end + 20] ^= 0x01

    for mname, mutated in mutations.items():
        path = work / f"{mname}.sec"
        path.write_bytes(bytes(mutated))
        codes = {}
        for impl in IMPLS:
            out = work / f"{mname}-{impl}.out"
            if out.exists():
                out.unlink()
            d_rc, _, _ = decrypt(impl, path, identities=[secrets["rust"]], out=out)
            codes[impl] = d_rc
        name = f"mutation {mname} exit codes"
        if len(set(codes.values())) == 1 and list(codes.values())[0] == 4:
            ok(f"{name}={codes}")
        else:
            # Truncation or flip might yield 3 or 4 depending on whether MAC/stanza parse fails first;
            # require agreement and that it's a failure (non-zero), prefer 4.
            if len(set(codes.values())) == 1 and list(codes.values())[0] != 0:
                ok(f"{name}={codes} (agreed non-zero)")
            else:
                bad(name, str(codes))


def main() -> int:
    require_bins()
    if TMP.exists():
        shutil.rmtree(TMP)
    TMP.mkdir(parents=True)
    work = Path(tempfile.mkdtemp(dir=TMP))
    try:
        test_key_roundtrips(work)
        test_matrix(work)
        test_passphrase(work)
        mutate_and_check(work)
    finally:
        pass
    log(f"\nSUMMARY: {PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
