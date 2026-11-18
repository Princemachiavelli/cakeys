# Review: crates/camigrate/tests/from_files.rs (277 lines)

Reviewed 2026-11-18 [read]. Summary: `camigrate import` of objects whose `origin = "file"`: a
server bundle, an AES key and a data file onto SoftHSM (and kryoptic), every private-key file
format, and every spelling of the AES key. The asymmetric and public objects' identities are
checked against independent oracles (the fixture SPKI, certificate and data hashes); the AES
key's identity is not, and the tests skip under a condition other than the one their header
states.

## Findings

### F1. The AES key's identity is never checked against the key in the file — risk

**Verification:** confirmed (downgraded to practice). The integration test has no independent oracle for `kek`/`k` (`from_files.rs:94`, `:256-265`), but the scenario it names, a decoding slip common to every spelling, is caught by the unit test `secret_keys_are_their_value_and_data_objects_their_bytes` (`crates/camigrate/src/keyfile.rs:635-653`), which asserts each hex/base64 spelling and the raw read decode to exactly `aes256.key`'s bytes. What stays unguarded is only the step from those bytes to the token object (the ID is token-derived, `host_ids` is `[]` at `:640`), which the suggested `aes_commitment` assert would close cheaply. [read]
`crates/camigrate/tests/from_files.rs:94`, `:249-265`. For `web`, `web-cert` and `note` the
locked ID is compared with an independent hash of the fixture (`:88-93`). For `kek` the test
asserts only that a `kcv-ecb` ID exists; `cakeys check` then compares the token with the lock,
which was computed from that same token. In `every_spelling_of_a_secret_key_imports_as_the_same_key`
the five spellings are compared with each other, the raw bytes being the first use. So a
decoding bug common to every spelling (a byte-order or length slip when reading the raw file)
records the wrong key, and every check passes. The independent oracle exists:
`common::aes_commitment(key, "kcv-ecb")` (`crates/cli/tests/common/mod.rs:587-625`). Fix: assert
`lock.objects.kek.ids.kcv-ecb == aes_commitment(&fs::read(fixture("aes256.key")), "kcv-ecb")`,
and the same for `k` after the spellings loop. [read]

### F2. The tests skip with fewer than two references, though they need only SoftHSM — practice

`crates/camigrate/tests/from_files.rs:5`, `:62-67`, `:145-149`, `:220-224`. All three call
`common::xref::env`, which returns `None` unless two reference tokens are set
(`crates/cli/tests/common/xref.rs:62-65`). The header says "Skipped without the SoftHSM
reference", and two of the tests use SoftHSM alone. A run with only `CAKEYS_TEST_MODULE` set
(and `CAKEYS_TEST_REQUIRE=1`) skips all three silently, the REQUIRE gate notwithstanding,
because no variable is missing. Fix: build the `Env` from the SoftHSM variable alone for the
single-token tests (an `env_with(name, &["softhsm"])` helper; see dry_run.rs F3), or correct the
header. [read]

### F3. Re-runs and refusals check exit and message, not the lock bytes — nit

`crates/camigrate/tests/from_files.rs:111-113` ("a re-run imports nothing") and `:73-83` (the two
15 refusals) assert the exit code and a substring, not that `keys.lock` is byte-identical, as
dry_run.rs does after each re-run and refusal and as `:129-136` here does for the 10 case. The
dry-run twin covers the dry run, not the real run. Fix: read the lock before and compare after.
[read]

## Design

- None.

## Checked, no issue

- Exit codes are asserted alongside every message (15 for plaintext without the flag, 17 for an
  unread format or wrong encoding, 10 for other material) and the target label is checked empty
  after each refusal.
- The PKCS#12 case checks the "passphrase only from the command line" refusal (17) before the
  import that succeeds.
- Each successful import records `provenance.origin` with method and exposure, and `cakeys check`
  accepts it; the second token (kryoptic) is checked against the lock the first wrote.
