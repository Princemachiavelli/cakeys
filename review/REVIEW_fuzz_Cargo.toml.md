# Review: fuzz/Cargo.toml (104 lines)

Reviewed 2026-11-18 [read]. Summary: the cargo-fuzz crate, its own workspace and lock (so
`libfuzzer-sys` stays out of the product graph), path dependencies on core, camigrate,
tpm2-pkcs11, ykcs11 and caprobe, and one `[[bin]]` per target (12, matching
`fuzz/fuzz_targets/`).

## Findings

### F1. The untrusted-file parser camigrate reads has no target — practice

`fuzz/Cargo.toml` (target list). `camigrate::file::read` (`crates/camigrate/src/file.rs:160`)
parses operator-supplied key files: PEM, encrypted PKCS#8 (PBES2, PBKDF2 or scrypt) and
PKCS#12 (MAC data, `ContentInfo`s, encrypted containers, safe bags, cert bags), with its own
bounds on iteration counts and scrypt parameters (B19). It is the most hostile-input-facing
parser in the tree and is unfuzzed; ISSUES.md's "fuzz the remaining parsers" item listed only
the PIV chain, P-521 fix-up and profiles. The KDF cost makes plain fuzzing slow; a
`#[cfg(fuzzing)]` cap on `MAX_ITERATIONS` (and the scrypt bound), with a `fuzzing` module as the
other crates have, would make it practical, and its property can be "opens, or refused with 17,
never a panic or a hang". Also unfuzzed but cheaper: the signature verifiers that read token
output (`cakeys_core::pop::verify`, `sig::ecdsa`) on arbitrary `(spki, msg, sig)`.
[read]

**Fixed (2026-11-18):** Verified fixed (2026-11-18), unmarked until now.

## Design

- Of the 12 targets, 6 assert a property beyond "does not panic" (`attest_encoding`, `hex`,
  `p521_point`, `profile`, `public_key`, `certificate`, the last two the same idempotence); the
  other 6 assert only no panic or the exit code. Two of those (`lock`, `bundle`) have a writer
  in cakeys and could assert a round trip (see their reviews).
- Without a sanitizer (ISSUES.md "Unsafe code and other tools"), `tpms_attest` cannot detect
  memory errors in the C unmarshallers it mainly exercises.

## Checked, no issue

- Each `[[bin]]` path exists and each target file has a `[[bin]]` (12 and 12).
- `camigrate` and `caprobe` are pulled with `default-features = false`, keeping the fuzz build
  light.
