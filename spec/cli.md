# secreto CLI (normative)

Implementations MUST provide two programs: `secreto` and `secreto-keygen`.

## Synopsis

```
secreto [-e] (-r RECIPIENT | -R FILE)... [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]
secreto [-e] -p [--sign KEYFILE] [--pad] [-a] [-o OUT] [IN]
secreto -d (-i FILE)... | -p [--verify SIGNER_PUB] [-o OUT] [IN]
secreto-keygen [-o OUT]
secreto-keygen -y [IN]
secreto-keygen --signing [-o OUT]
secreto-keygen --signing -y [IN]
```

If neither `-e` nor `-d` is given, `-e` is implied when recipients/`-p` are
present; otherwise usage error.

`IN` defaults to stdin. `-` means stdin/stdout as appropriate.

## Flags

| Flag | Meaning |
|------|---------|
| `-e` | Encrypt |
| `-d` | Decrypt |
| `-r RECIPIENT` | Encrypt to Bech32 recipient (repeatable) |
| `-R FILE` | Read recipients from file (one per line; `#` comments) |
| `-i FILE` | Decrypt with identity file (repeatable) |
| `-p` | Passphrase mode |
| `-a` | ASCII armor output (encrypt only) |
| `-o OUT` | Output path |
| `--pad` | Apply Padmé length padding (encrypt only) |
| `--sign KEYFILE` | Sign with signing secret key file |
| `--verify PUB` | Require and verify signature from this `secretosig` public key |

Encrypt MUST receive at least one of: one or more `-r`/`-R`, or `-p`.
`-p` MUST NOT be combined with `-r`/`-R`.

Decrypt MUST receive at least one `-i` or `-p`.

## secreto-keygen

| Invocation | Behavior |
|------------|----------|
| (default) | Generate identity; write secret key to `-o` or stdout; print recipient to stderr |
| `-y [IN]` | Read identity from IN/stdin; print recipient to stdout |
| `--signing` | Generate signing keypair; write secret to `-o`/stdout; print `secretosig` to stderr |
| `--signing -y [IN]` | Read signing secret; print `secretosig` to stdout |

Generated secret key files MUST be created with mode `0600` when writing to
a filesystem path.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage error or invalid key/recipient file |
| 2 | I/O error |
| 3 | No matching identity / wrong passphrase |
| 4 | Format or authentication failure |
| 5 | Signature missing, invalid, or wrong signer |

## Errors

One line on stderr:

```
secreto: error: <message>
```

Exit codes are normative; message text is not. Secrets MUST NOT appear in
messages.

## Passphrase input

1. If `SECRETO_PASSPHRASE_FD` is set to a decimal file descriptor number,
   read the passphrase from that FD (content up to EOF or first LF; strip
   one trailing LF/CRLF).
2. Otherwise read from `/dev/tty` with echo disabled (encrypt: confirm by
   reading twice and requiring equality).

Passphrases MUST NOT be accepted via argv.

## Output rules

- Refuse to write binary (non-armored) ciphertext to a terminal unless
  `-a` is set (exit 1).
- `-o` MUST write to a temporary file in the same directory (`O_EXCL`,
  mode `0600`), `fsync`, rename into place on success, and unlink on
  failure.
- Warn on stderr if an identity or signing-key input file is group- or
  world-readable.

## Signature / verify behavior

- With `--verify`: do not release content until verification succeeds.
  When `-o` is set, buffer in the temp file. When writing to stdout,
  buffer in memory up to 256 MiB; if content would exceed that, exit 1
  asking for `-o`.
- Without `--verify`, a signed file decrypts successfully and prints a
  warning including the hex signer_id.

## Environment

| Variable | Meaning |
|----------|---------|
| `SECRETO_PASSPHRASE_FD` | FD number for passphrase |
