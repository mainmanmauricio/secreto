"""``secreto-keygen`` (spec/cli.md)."""

from __future__ import annotations

import argparse
import sys

from . import __version__, keys
from .cli import (
    _Parser,
    die,
    is_std,
    read_secret_key_input,
    write_new_secret_file,
    write_stdout,
)
from .error import InvalidKeyError, SecretoError
from .sign import SigningKey

PROG = "secreto-keygen"
USAGE = (
    "secreto-keygen [-o OUT]\n"
    "       secreto-keygen -y [IN]\n"
    "       secreto-keygen --signing [-o OUT]\n"
    "       secreto-keygen --signing -y [IN]"
)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog=PROG,
        usage=USAGE,
        description="Generate secreto identities and signing keys.",
        allow_abbrev=False,
    )
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument("--signing", action="store_true")
    p.add_argument("-y", dest="convert", action="store_true")
    p.add_argument("-o", dest="output", metavar="OUT")
    p.add_argument("input", nargs="?", metavar="IN")
    return p


def _emit_secret(out: str | None, secret: str) -> None:
    data = (secret + "\n").encode("ascii")
    if is_std(out):
        write_stdout(data)
    else:
        write_new_secret_file(out, data)  # type: ignore[arg-type]


def run(argv: list[str] | None) -> None:
    a = build_parser().parse_args(argv)
    if a.convert:
        if a.output is not None:
            raise InvalidKeyError("-o is not valid with -y")
        text = read_secret_key_input(PROG, a.input)
        name = a.input if not is_std(a.input) else "stdin"
        out = ""
        try:
            if a.signing:
                out = keys.signer_public_to_bech32(keys.parse_signing_key(text).public_key()) + "\n"
            else:
                for ident in keys.parse_identities(text):
                    out += ident.recipient().to_bech32() + "\n"
        except SecretoError as e:
            raise type(e)(f"{name}: {e}") from None
        write_stdout(out.encode("ascii"))
        return
    if a.input is not None:
        raise InvalidKeyError("IN is only valid with -y")
    if a.signing:
        sk = SigningKey.generate()
        _emit_secret(a.output, keys.signing_key_to_bech32(sk))
        print(keys.signer_public_to_bech32(sk.public_key()), file=sys.stderr)
    else:
        ident = keys.Identity.generate()
        _emit_secret(a.output, ident.to_bech32())
        print(ident.recipient().to_bech32(), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    try:
        run(argv)
        return 0
    except SecretoError as e:
        return die(PROG, e)
    except BrokenPipeError:
        return 2


def entry() -> None:  # pragma: no cover
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    entry()
