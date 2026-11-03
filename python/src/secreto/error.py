# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Errors carrying the normative exit codes of spec/cli.md."""


class SecretoError(Exception):
    """Base class; ``exit_code`` is the process exit status."""

    exit_code = 1


class InvalidKeyError(SecretoError):
    """Usage error or invalid key / recipient / identity input (exit 1)."""

    exit_code = 1


class IoError(SecretoError):
    """I/O failure (exit 2)."""

    exit_code = 2


class NoMatchError(SecretoError):
    """No matching identity or wrong passphrase (exit 3)."""

    exit_code = 3

    def __init__(self, message: str = "no matching identity or wrong passphrase"):
        super().__init__(message)


class FormatError(SecretoError):
    """Malformed or unauthenticated ciphertext (exit 4)."""

    exit_code = 4


class SignatureError(SecretoError):
    """Signature missing, invalid, or wrong signer (exit 5)."""

    exit_code = 5
