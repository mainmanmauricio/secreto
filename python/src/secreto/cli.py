# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""``secreto`` command-line interface (spec/cli.md)."""

from __future__ import annotations

import argparse
import errno
import os
import stat
import sys
from pathlib import Path

from . import __version__, keys
from .decrypt import decrypt_to
from .encrypt import encrypt_to
from .error import InvalidKeyError, IoError, SecretoError

ENV_PASSPHRASE_FD = "SECRETO_PASSPHRASE_FD"
MAX_STDOUT_BUFFER = 256 * 1024 * 1024
MAX_PASSPHRASE_LEN = 1 << 20

USAGE = (
    "secreto [-e] (-r RECIPIENT | -R FILE)... [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n"
    "       secreto [-e] -p [--memory MIB] [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]\n"
    "       secreto -d (-i FILE)... | -p [--verify SIGNER_PUB] [-o OUT] [IN]"
)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def warn(prog: str, msg: str) -> None:
    print(f"{prog}: warning: {msg}", file=sys.stderr)


def die(prog: str, err: SecretoError) -> int:
    one_line = "".join(" " if (c.isprintable() is False) else c for c in str(err))
    print(f"{prog}: error: {one_line}", file=sys.stderr)
    return err.exit_code


def is_std(path: str | None) -> bool:
    return path is None or path == "-"


def read_input(path: str | None) -> bytes:
    try:
        if is_std(path):
            return sys.stdin.buffer.read()
        with open(path, "rb") as f:  # type: ignore[arg-type]
            return f.read()
    except OSError as e:
        raise IoError(f"{path or 'stdin'}: {e.strerror or e}") from None


def read_text_file(path: str | os.PathLike) -> str:
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        raise IoError(f"{path}: {e.strerror or e}") from None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidKeyError(f"{path}: not valid UTF-8") from None


def read_secret_key_file(prog: str, path: str | os.PathLike) -> str:
    try:
        if os.stat(path).st_mode & 0o077:
            warn(prog, f"{path} is group- or world-readable; consider chmod 600")
    except OSError:
        pass
    return read_text_file(path)


def read_secret_key_input(prog: str, path: str | None) -> str:
    if is_std(path):
        raw = read_input(None)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidKeyError("stdin: not valid UTF-8") from None
    return read_secret_key_file(prog, path)  # type: ignore[arg-type]


def _read_passphrase_fd(value: str) -> bytes:
    if not value or not value.isascii() or not value.isdigit():
        raise InvalidKeyError(f"{ENV_PASSPHRASE_FD} must be a decimal fd number")
    fd = int(value)
    buf = bytearray()
    try:
        try:
            while len(buf) < MAX_PASSPHRASE_LEN:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in chunk:
                    break
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    except OSError as e:
        raise IoError(f"reading passphrase from fd {fd}: {e.strerror or e}") from None
    nl = buf.find(b"\n")
    if nl >= 0:
        del buf[nl:]
        if buf.endswith(b"\r"):
            buf.pop()
    return bytes(buf[:MAX_PASSPHRASE_LEN])


def _read_passphrase_tty(prompt: str) -> bytes:
    import termios

    try:
        tty = open("/dev/tty", "r+b", buffering=0)
    except OSError:
        raise InvalidKeyError(
            f"no terminal available; set {ENV_PASSPHRASE_FD} to read the passphrase from a descriptor"
        ) from None
    with tty:
        fd = tty.fileno()
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ECHO
        try:
            termios.tcsetattr(fd, termios.TCSAFLUSH, new)
            tty.write(prompt.encode())
            line = b""
            while not line.endswith(b"\n"):
                ch = tty.read(1)
                if not ch:
                    break
                line += ch
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
            tty.write(b"\n")
    return line.rstrip(b"\r\n")


def read_passphrase(confirm: bool) -> bytes:
    value = os.environ.get(ENV_PASSPHRASE_FD)
    if value is not None:
        return _read_passphrase_fd(value)
    first = _read_passphrase_tty("Passphrase: ")
    if confirm:
        second = _read_passphrase_tty("Confirm passphrase: ")
        if first != second:
            raise InvalidKeyError("passphrases do not match")
    return first


def write_stdout(data: bytes) -> None:
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except OSError as e:
        raise IoError(f"writing stdout: {e.strerror or e}") from None


def write_output(out: str | None, data: bytes) -> None:
    """Write to stdout, or atomically (O_EXCL temp 0600, fsync, rename) to ``out``."""

    def _write(f) -> None:
        f.write(data)

    with_output(out, _write)


def open_input(path: str | None):
    """Open stdin or a file for streaming reads (caller must close file objects)."""
    if is_std(path):
        return sys.stdin.buffer, False
    try:
        return open(path, "rb"), True  # type: ignore[arg-type]
    except OSError as e:
        raise IoError(f"{path}: {e.strerror or e}") from None


def with_output(out: str | None, write_fn) -> None:
    """Call ``write_fn(fileobj)`` with stdout or an atomic temp file."""
    if is_std(out):
        try:
            write_fn(sys.stdout.buffer)
            sys.stdout.buffer.flush()
        except OSError as e:
            raise IoError(f"writing stdout: {e.strerror or e}") from None
        return
    target = Path(out)  # type: ignore[arg-type]
    directory = target.parent if str(target.parent) else Path(".")
    base = target.name
    if not base:
        raise InvalidKeyError(f"{out}: invalid output path")
    tmp = None
    fd = -1
    for attempt in range(64):
        cand = directory / f".{base}.tmp.{os.getpid()}.{os.urandom(4).hex()}.{attempt}"
        try:
            fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            tmp = cand
            break
        except FileExistsError:
            continue
        except OSError as e:
            raise IoError(f"{cand}: {e.strerror or e}") from None
    if tmp is None:
        raise IoError("could not create a temporary output file")
    committed = False
    try:
        try:
            with os.fdopen(fd, "wb") as f:
                write_fn(f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
            committed = True
        except OSError as e:
            raise IoError(f"{out}: {e.strerror or e}") from None
    finally:
        if not committed:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def write_new_secret_file(path: str, data: bytes) -> None:
    """Create ``path`` (mode 0600, must not exist) and write ``data``."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        raise IoError(f"{path}: {e.strerror or e}") from None
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise IoError(f"{path}: {e.strerror or e}") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # type: ignore[override]
        raise InvalidKeyError(message.splitlines()[0] if message else "invalid arguments")

    def exit(self, status: int = 0, message: str | None = None):  # type: ignore[override]
        if message:
            print(message, file=sys.stderr, end="")
        sys.exit(status)


def parse_args_or_exit(parser: argparse.ArgumentParser, argv: list[str] | None):
    return parser.parse_args(argv)


# --------------------------------------------------------------------------
# secreto
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="secreto",
        usage=USAGE,
        description="Encrypt and decrypt files in the secreto/v1 format.",
        allow_abbrev=False,
    )
    p.add_argument("--version", action="version", version=f"secreto {__version__}")
    p.add_argument("-e", dest="encrypt", action="store_true", help="Encrypt")
    p.add_argument("-d", dest="decrypt", action="store_true", help="Decrypt")
    p.add_argument("-r", dest="recipients", action="append", default=[], metavar="RECIPIENT")
    p.add_argument("-R", dest="recipient_files", action="append", default=[], metavar="FILE")
    p.add_argument("-i", dest="identities", action="append", default=[], metavar="FILE")
    p.add_argument("-p", dest="passphrase", action="store_true")
    p.add_argument("--memory", type=int, metavar="MIB", dest="memory")
    p.add_argument("-a", dest="armor", action="store_true")
    p.add_argument("-o", dest="output", metavar="OUT")
    p.add_argument("--pad", action="store_true")
    p.add_argument("--sign", metavar="KEYFILE")
    p.add_argument("--verify", metavar="SIGNER_PUB")
    p.add_argument("input", nargs="?", metavar="IN")
    return p


def _argon_from_args(a: argparse.Namespace) -> dict[str, int]:
    from . import argon

    if a.memory is None:
        return {"m_kib": argon.DEFAULT_M, "t": argon.DEFAULT_T, "p": argon.DEFAULT_P}
    if not a.passphrase:
        raise InvalidKeyError("--memory requires -p")
    if not (64 <= a.memory <= 4096):
        raise InvalidKeyError("--memory must be an integer between 64 and 4096 (MiB)")
    return {"m_kib": a.memory * 1024, "t": argon.DEFAULT_T, "p": argon.DEFAULT_P}


def _determine_mode(a: argparse.Namespace) -> str:
    has_rcpt = bool(a.recipients or a.recipient_files)
    if a.encrypt and a.decrypt:
        raise InvalidKeyError("-e and -d are mutually exclusive")
    if a.encrypt:
        return "encrypt"
    if a.decrypt:
        return "decrypt"
    if has_rcpt or a.passphrase:
        if a.identities:
            raise InvalidKeyError("-i requires -d")
        return "encrypt"
    raise InvalidKeyError("specify -e or -d (or recipients / -p to imply -e)")


def _load_recipients(a: argparse.Namespace) -> list[keys.Recipient]:
    out = []
    for r in a.recipients:
        try:
            out.append(keys.Recipient.from_bech32(r.strip()))
        except SecretoError as e:
            raise type(e)(f"-r: {e}") from None
    for f in a.recipient_files:
        text = read_text_file(f)
        try:
            out.extend(keys.parse_recipients(text))
        except SecretoError as e:
            raise type(e)(f"{f}: {e}") from None
    return out


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except (ValueError, AttributeError):
        return False


def _run_encrypt(a: argparse.Namespace) -> None:
    if a.identities:
        raise InvalidKeyError("-i is only valid with -d")
    if a.verify is not None:
        raise InvalidKeyError("--verify is only valid with -d")
    has_rcpt = bool(a.recipients or a.recipient_files)
    if a.passphrase and has_rcpt:
        raise InvalidKeyError("-p cannot be combined with -r/-R")
    if not a.passphrase and not has_rcpt:
        raise InvalidKeyError("encryption requires at least one -r/-R recipient or -p")
    if not a.armor and is_std(a.output) and _stdout_is_tty():
        raise InvalidKeyError("refusing to write binary ciphertext to a terminal; use -a or -o")
    recips = _load_recipients(a) if has_rcpt else []
    signer = None
    if a.sign is not None:
        text = read_secret_key_file("secreto", a.sign)
        try:
            signer = keys.parse_signing_key(text)
        except SecretoError as e:
            raise type(e)(f"{a.sign}: {e}") from None
    argon_kw = _argon_from_args(a)
    pw = None
    if a.passphrase:
        pw = read_passphrase(True)
        if not pw:
            raise InvalidKeyError("empty passphrase")
    inp, close_inp = open_input(a.input)
    try:

        def _enc(out) -> None:
            encrypt_to(
                inp,
                out,
                recipients=recips or None,
                passphrase=pw,
                pad=a.pad,
                signer=signer,
                armored=a.armor,
                **argon_kw,
            )

        with_output(a.output, _enc)
    finally:
        if close_inp:
            inp.close()


def _load_verify_key(arg: str):
    s = arg.strip()
    if not arg.startswith("secretosig1") and os.path.isfile(arg):
        lines = [
            ln.strip()
            for ln in read_text_file(arg).splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if not lines:
            raise InvalidKeyError(f"{arg}: no signer public key found")
        if len(lines) > 1:
            raise InvalidKeyError(f"{arg}: multiple keys in file")
        s = lines[0]
    try:
        return keys.signer_public_from_bech32(s)
    except SecretoError as e:
        raise type(e)(f"--verify: {e}") from None


def _run_decrypt(a: argparse.Namespace) -> None:
    if a.recipients or a.recipient_files:
        raise InvalidKeyError("-r/-R are only valid when encrypting")
    if a.armor or a.pad or a.sign is not None or a.memory is not None:
        raise InvalidKeyError("-a, --pad, --sign and --memory are only valid when encrypting")
    if a.passphrase and a.identities:
        raise InvalidKeyError("-p cannot be combined with -i")
    if not a.passphrase and not a.identities:
        raise InvalidKeyError("decryption requires at least one -i FILE or -p")
    ids: list[keys.Identity] = []
    for f in a.identities:
        text = read_secret_key_file("secreto", f)
        try:
            ids.extend(keys.parse_identities(text))
        except SecretoError as e:
            raise type(e)(f"{f}: {e}") from None
    verify = _load_verify_key(a.verify) if a.verify is not None else None
    pw = read_passphrase(False) if a.passphrase else None
    inp, close_inp = open_input(a.input)
    try:
        if is_std(a.output) and verify is not None:
            import io

            buf = io.BytesIO()
            meta = decrypt_to(inp, buf, identities=ids, passphrase=pw, verify=verify)
            content = buf.getvalue()
            if len(content) > MAX_STDOUT_BUFFER:
                raise InvalidKeyError(
                    "verified content exceeds 256 MiB; use -o to write to a file"
                )
            if meta.signer_id is not None and not meta.verified:
                warn(
                    "secreto",
                    f"file is signed by signer_id {meta.signer_id.hex()}; "
                    "signature NOT verified (use --verify)",
                )
            write_output(None, content)
        else:
            meta_holder: list = []

            def _dec(out) -> None:
                meta_holder.append(
                    decrypt_to(inp, out, identities=ids, passphrase=pw, verify=verify)
                )

            with_output(a.output, _dec)
            meta = meta_holder[0]
            if meta.signer_id is not None and not meta.verified:
                warn(
                    "secreto",
                    f"file is signed by signer_id {meta.signer_id.hex()}; "
                    "signature NOT verified (use --verify)",
                )
    finally:
        if close_inp:
            inp.close()


def main(argv: list[str] | None = None) -> int:
    try:
        a = build_parser().parse_args(argv)
        mode = _determine_mode(a)
        if mode == "encrypt":
            _run_encrypt(a)
        else:
            _run_decrypt(a)
        return 0
    except SecretoError as e:
        return die("secreto", e)
    except BrokenPipeError:
        return 2
    except KeyboardInterrupt:
        return 130


def entry() -> None:  # pragma: no cover
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    entry()
