# References (pinned)

These versions define secreto/v1. Implementations MUST use the algorithms as
specified by these snapshots even if later drafts change.

## Normative

1. **age format inspiration** — [c2sp.org/age](https://c2sp.org/age)
   (age-encryption.org/v1). Structure, stanza syntax, STREAM chunking, and
   many rejection rules are adapted from age. secreto/v1 is **not**
   age-compatible.

2. **HPKE** — RFC 9180, Hybrid Public Key Encryption.
   <https://www.rfc-editor.org/rfc/rfc9180>

3. **PQ HPKE KEMs** — `draft-ietf-hpke-pq-03`
   <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03>
   MLKEM1024-P384 as HPKE KEM ID `0x0051`.

4. **Concrete hybrid KEMs** — `draft-irtf-cfrg-concrete-hybrid-kems-04`
   <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04>
   MLKEM1024-P384 CG construction, label `MLKEM1024-P384`, Appendix B.3
   test vectors.

5. **Hybrid KEM frameworks** — `draft-irtf-cfrg-hybrid-kems-12`
   <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12>
   CG framework with C2PRI combiner.

6. **ML-KEM** — FIPS 203 (final).

7. **ML-DSA** — FIPS 204 (final).

8. **Argon2** — RFC 9106.

9. **ChaCha20-Poly1305** — RFC 8439.

10. **HKDF** — RFC 5869 (with SHA-512).

11. **HMAC** — RFC 2104 (with SHA-512).

12. **Bech32** — BIP173, without the 90-character length limit (same
    relaxation as age).

13. **PEM armor** — RFC 7468 Section 3 (strict).

14. **Padmé** — length-hiding padding from
    "Padding Oracle Attacks: the Good, the Bad, and the Ugly" style
    constructions / age-adjacent literature: see format.md for the exact
    formula used by secreto.

15. **STREAM** — Online Authenticated-Encryption and its Nonce-Reuse
    Misuse-Resistance, eprint 2015/189; age's STREAM variant.

16. **P-384 / SEC1** — SP 800-186 and SEC 1 v2 (uncompressed point encoding).

## Informative

- age test kit layout: <https://age-encryption.org/testkit>
- NSA CNSA 2.0 (motivation for 256-bit / ML-KEM-1024 choices)
