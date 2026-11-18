# Review: crates/caprobe/tests/supports.rs (76 lines)

Reviewed 2026-11-18 [read]. Summary: `caprobe supports` against the embedded profiles: yes/no/
unknown as exit 0/15/16 for module profiles, a layer, a hardware pair and its hand-factored layer,
a class, a parameter set the profiles cannot decide, no module profile at all, `--profiles` with
a layer of one's own, and `--token` by keys.toml's `provider` with its refusals (17) and
`caps` without keys.toml (2). For `supports` the exit code is the answer, and the cases are
chosen so a wrong reason mostly gives a different code. One environment leak.

## Findings

### F1. `CAKEYS_CONFIG` from the developer's environment leaks into the profile-only runs — practice

`crates/caprobe/tests/supports.rs:12-17`, `:63`. `supports()` runs `caprobe supports ...` without
`--config` and without removing `CAKEYS_CONFIG`. When it is set (a developer with a keys.toml
exported, which `nix develop` or a direnv might do), `dispatch` loads that file
(`crates/caprobe/src/lib.rs:171-172`), activates its `profileDirs`, and can answer differently or
fail with 17 on a broken config. The last test already does `env_remove("CAKEYS_CONFIG")` for
`caps` (`:74`), which shows the concern is known. Fix: `env_remove("CAKEYS_CONFIG")` in
`supports()` too (and in `ask`, which passes `--config` explicitly but could still read other
`CAKEYS_*` variables). [read]

### F2. Codes only; which profile or row answered is not checked — nit

`crates/caprobe/tests/supports.rs:21-36`. Each case asserts the exit code. For most cases a wrong
path gives a different code (an ignored `--layer` turns 15 into 0 or 16), but the two 16 cases
(`CKM_NOT_A_MECHANISM`, `CKP_PKCS5_PBKD2_HMAC_SHA1`) and the no-profile case would also be 16 if
the profile were not found at all. docs/CAPROBE.md describes `supports` printing its evidence;
asserting one line of stdout for the 16 cases (e.g. that `softhsm/2.7` was the profile
consulted) would separate "unknown to the profile" from "no profile". [read]

### F3. Scratch directories bypass `common::test_dir` — nit

`crates/caprobe/tests/supports.rs:43`, `:55`. Fixed names under `CARGO_TARGET_TMPDIR`
(`supports-profiles`, `supports-token`) rather than `common::test_dir(name)`, which prefixes the
package and binary so suites never share a directory (`crates/cli/tests/common/mod.rs:343-349`).
No collision today. [read]

## Design

- None.

## Checked, no issue

- No token, no skip: these run under any `cargo test`, as the header says.
- docs/CAPROBE.md:21-23 (0 yes, 15 no, 16 unknown) is covered for all three codes; the doc's
  "answers cite the deciding profile" is the part F2 says is not asserted.
- The `--token` refusals assert both the code (17) and the reason; `caps` without keys.toml is
  clap's usage error (2).
- `supports_reads_profiles_from_a_directory` discriminates: SoftHSM alone says yes to
  `CKM_SHA512_HMAC`, so 15 can only come from the added layer.
