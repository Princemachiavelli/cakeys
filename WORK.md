# WORK.md — in-progress: PROVIDERS phase 3 (the probe)

Scope: implementing docs/PROVIDERS.md phase 3 — the `cakeys probe` tool that generates the
committed module profiles, plus the conformance tests and docs that go with it. Phases 0–2
are already committed (`0b4cc2c`, `68f16d0`). Nothing below is committed yet.

## Ground rules (from the user)

- **Committed profiles are tool output, never hand-edited.** Ad-hoc probe runs are fine for
  developing the probe; maintenance is `probe --write --diff <name> --out <file>`.
- Keep the profile system independent of the runtime code; flag structural changes instead
  of silently making them.
- Commit each phase independently with a short lowercase message (repo style), e.g.
  "PROVIDERS phase 3: the probe, generated profiles and conformance".
- D8 (lock provenance profile-name field) and the `--config`-required CLI restructuring are
  deferred until after phase 3 is committed.

## Done

- **Probe engine** — `crates/pkcs11/src/probe.rs`:
  - Read-only probes always run; write probes (generate per curve/RSA size, advertised
    secret-key gens, OAEP wrap round-trips, unwrap-template rule) run only on a token
    keys.toml marks `scratch = true`; refused (exit 17) otherwise. SO-only providers
    (ykcs11 on hardware) are refused for `--write` by design.
  - Every run cleans up after itself; a leftover check turns "delete really deletes" into a
    note. Notes are deterministic (serial number dropped; NUL padding stripped).
  - Wrapping: public half wraps, private half unwraps (OAEP is encryption). **Fixed in the
    2026-11-13 review:** the transport key put CKA_WRAP *and* CKA_UNWRAP on the private
    template — SoftHSM's "refusal" was CKR_ATTRIBUTE_TYPE_INVALID for CKA_WRAP on a private
    key, and kryoptic's "rejects the public handle" / OAEP CKR_GENERAL_ERROR came from a public
    half without CKA_WRAP. Now: public gets CKA_ENCRYPT+CKA_WRAP, private CKA_DECRYPT+
    CKA_UNWRAP (bare templates as fallback); no wrong-half handle fallbacks; OAEP SHA-256
    uses MGF1-SHA256 (core's `OaepHash`: MGF1 of the same hash); the unwrap-template rule
    uses the first hash that round-tripped (was hard-coded SHA-1); OAEP failures are one
    `notes.oaep` line (what `Effective::oaep` cites — the `oaep-<hash>` keys were dead).
    Re-probed: kryoptic does OAEP SHA-1 **and** SHA-256 and accepts CKA_VALUE_LEN in unwrap
    templates; SoftHSM is still SHA-1 only (SHA-256 = CKR_ARGUMENTS_BAD with matched MGF).
  - Notes carry `CKR_*` names (`ckr()`), not cryptoki's Display prose — the prose would make
    regeneration non-identical on a cryptoki bump with no behaviour change.
  - `--write` refuses a token with no PIN (every generation would fail CKR_USER_NOT_LOGGED_IN
    and be recorded as module refusals).
- **Diff** — `crates/profile/src/diff.rs` (`cakeys_profile::diff`): compares observable rows
  only (match, advertise, subtract.mechanisms, generate rows, wrap.oaep, unwrap.refuse);
  notes/partial/migration never compared. Empty diff = conformance.
- **Emitter** — `crates/profile/src/profile.rs` `Profile::to_toml`: generated-header, only
  non-empty sections. Now escapes every string (`toml_str`/`toml_list`): quotes, backslashes
  and control chars — needed because tpm2-pkcs11's token model is `"SW   TPM"` NUL-padded
  (TPM vendor-string properties), which once made the committed profile unparsable TOML and
  broke `Set::embedded()` (that was the mystery exit-17).
  Round-trip test added (`emitting_and_parsing_round_trips_module_supplied_text`).
- **CLI** — `crates/cli/src/lib.rs` `probe` subcommand: `--token/--write/--out/--diff/
  --profiles`. Regeneration flow: adopt the claimed profile's name (kryoptic reports 0.0),
  preserve the file's `[migration]` claims (the only non-probe section), **write before the
  diff verdict** so regeneration works amid drift; diff failure is exit 15.
- **Plumbing** — `Token.advertised` names field + `raw()` session accessor;
  `TokenCfg.scratch` (crates/core/src/config.rs).
- **Regenerated profiles** (2026-11-13, second design round below, via
  `probe --write --diff <name> --out <file>`): softhsm/2.7, kryoptic/1.5 and
  tpm2-pkcs11/1.10+swtpm conform (exit 0; the tpm2 read-only `--diff` too) and regenerate
  **byte-identically** on a second run. profiles/hardware/swtpm.toml is hand-maintained again
  (HEAD's content + a header saying it is a manual factoring, with the [src] evidence).
  ykcs11/2.7 stays hand-maintained claims-only (probe refuses SO-only modules).
- **checks.profiles**: `CKM_SHA512_HMAC` 16→0 and `--class pq` 16→15 (softhsm is probed, not
  partial); the tpm2 case is now `--profile tpm2-pkcs11/1.10+swtpm --bits 4096` plus the
  hand layer `--profile tpm2-pkcs11 --layer swtpm --bits 4096` (both 15). All pass against
  the debug binary (bar `CKK_SHA512_HMAC`, 15 locally because local cargo links the
  unpatched cryptoki; 16 under Nix).
- **Gates — green locally**: `cargo fmt`; clippy `--workspace --all-targets -D warnings`;
  `cargo test --workspace` (all pass). Caveat: the token-backed suites (softhsm.rs,
  kryoptic.rs, tpm2.rs) skip without their env (0.00s) — they only really run under Nix.

## Review 2026-11-13: issues found, and how each was resolved

Probe bugs (fixed, see Done → Probe engine): wrong-half CKA_WRAP template, MGF1-SHA1 with
SHA-256, hard-coded SHA-1 unwrap rule, Display prose in notes, dead `notes.oaep` lookup,
`--write` without a PIN. The kryoptic "OAEP fails" result was one of these.

Structural, decided by the user (two rounds; the first round's `--hardware-out` routing was
replaced — see "Why the routing went" below):

- **A profile is what the probe measured: the module on one kind of hardware, together.**
  The probe cannot tell the module's refusal from the hardware's (same CKR codes), so it
  doesn't try. One observed profile per pair, module first so family lookup keeps working:
  `tpm2-pkcs11/1.10+swtpm` (file profiles/modules/tpm2-pkcs11/1.10+swtpm.toml). Software
  tokens keep plain names (the module *is* the hardware). New pair: `probe --name <name>`.
  Splitting a pair into module + hardware is a **hand step** — profiles/hardware/swtpm.toml
  is one, marked never-generated. (Automatable only per vendor and outside PKCS#11, e.g.
  `tpm2_getcap ecc-curves` — not done.) This revises PROVIDERS.md D10 (doc update pending).
- **Match keys: record all four, prefer the most.** `MatchInfo` = manufacturer,
  module-version (omitted when the module reports 0.0), model, firmware — the probe always
  writes them. `resolve()` takes `Option<&TokenInfo>` (open: live token; `side_from_lock`:
  the lock's recorded token; transport: none). Among one family: version must not mismatch,
  then the most matching hardware keys (`Fit::hardware_keys`). Notes: version mismatch →
  "manufacturer alone"; hidden version + firmware match → "matched by the token's firmware
  (secondary evidence)". An exact `tokens.<t>.provider = "<profile>"` pin is taken as is.
- **No pair for this hardware → advertise only.** On a model/firmware mismatch the resolved
  copy keeps advertise/subtract/[migration] and drops generate, `wrap.oaep`,
  `unwrap.refuse` (→ unknown / Side's spec default), with a note. No token (transport file)
  → no hardware check. Tests `another_kind_of_hardware_keeps_the_advertisement_only` and the
  kryoptic 1.6 case.
- **RSA bounds: reported + observed.** `Token.rsa_bits` = `C_GetMechanismInfo` of
  `CKM_RSA_PKCS_KEY_PAIR_GEN` (read-only, so in read-only probes and the read-only diff);
  written as `min-bits`/`max-bits`. The sweep writes `can-bits`/`cannot-bits`.
  `Effective::generate(bits)`: observed size decides → outside reported range is no →
  between two observed successes is yes → other untried sizes unknown. Observed today:
  softhsm reports 512–16384, kryoptic 1024–16384, tpm2-on-swtpm 1024–3072 (tpm2-pkcs11 asks
  the TPM — the reported range alone already tells the truth there). So `--bits 8192` is
  unknown on softhsm, no on the swtpm pair.
- **R2 → `Option<Vec>`, emit `[]`.** `wrap.oaep` and `unwrap.refuse` are `Option`: absent =
  never probed (Side keeps its spec default; `--oaep` unknown), `[]` = probed, none
  (Side plans no OAEP method; `--oaep` answers no). Test `probed_empty_is_not_unprobed`.
- **R4 (fixed, tooling):** a read-only `--diff` could never conform. Now
  `cakeys_profile::diff::read_only` (match keys, advertise unless the claim is `partial`,
  reported key sizes) without `--write`.

Why the routing went: round one routed "refusals of advertised mechanisms" to a hardware
layer (`--hardware-out`). tpm2-pkcs11's source proved it wrong — secp256k1/brainpool are
refused by the module's own `nid_to_tpm2alg` (~/srcs/tpm2-pkcs11 src/lib/tpm.c:576–590)
before the TPM is asked, while the RSA cap is the TPM's (`handle_modulus` →
`tpm_find_max_rsa_keysize`, tpm.c:3142). No probe-only rule can attribute; hence pairs.

Small fixes: diff lines go to stderr; `--out` onto an unparsable file, or onto any existing
file without `--write`, is refused (17); the generated header names the `--diff` flow and
says a profile is module-on-hardware; `ckr()` pinned by
`notes_name_the_return_value_not_the_prose`; `diff` compares `restrict`, all match keys,
`can-bits`/`cannot-bits`. `Effective::generate` also honours a layer's `cannot` rows (kept
from round one: harmless, lets a hand-factored hardware layer refuse a curve).

Still open (small):

- Leftover `cakeys-probe-NN` objects from a killed run make the next run's leftover check
  emit a false "destroy" note. Check for the labels before probing (refuse or clean).
- Regeneration lost the human provenance comments (tpm2's `[migration]` `[src]` notes,
  "not P-521" rationale, the `secret-keys` tpm2_ptool guidance). Move them to docs.
- `C_GetMechanismInfo` is read only for RSA key-pair gen; EC field sizes and the rest are
  not recorded.

Plan gaps vs docs/PROVIDERS.md (phase 3 as written promises more than the probe does):

- **D4 claims are absent entirely**: no `CKO_PROFILE` read, no claims section in `Profile`.
- **No PQ parameter-set probes**, though kryoptic advertises ML-DSA/ML-KEM/SLH-DSA key-pair
  gen and the doc's headline gap is "parameter sets — find out by trying". `supports
  CKP_ML_DSA_65 --profile kryoptic/1.5` stays unknown.
- No AES key-wrap/KWP round-trips (the `kw` commitment and p11-kit's subtraction depend on
  them), no HMAC key-type generation (what the cryptoki layer is about), `C_GetMechanismInfo`
  for RSA key-pair gen only, no attribute-default or existing-object-encoding probes. "~25
  probes" today is ~6 families.
- D5's token-open drift assertion isn't scheduled in any phase (R4 now makes it possible).
- PROVIDERS.md wording drift: `[tokens.<t>.scratch]` and `--scratch` vs the implemented
  `scratch = true` and `--write`.
- The p11-kit path: probing through p11-kit records p11-kit's manufacturer/version and
  filtered advertise list under the module's name; the planned forwarded-advertise
  cross-check should be the only supported use, and `--out` onto a module profile refused.

## Conformance tests — done 2026-11-13

- `common::assert_profile_conforms` (tests/common/mod.rs): probe `--write --diff` → 0;
  regenerate a copy of the committed file → byte-identical (fails with the regeneration
  command on a hand edit — verified by editing one note); read-only `--diff` → 0; read-only
  `--out` onto the file → 17 and untouched.
- tests/reference/ `the_committed_profile_is_what_the_probe_observes` (softhsm + kryoptic via
  `Reference.profile`), plus `ref-anon --write` → 17 "not marked scratch".
- tests/tpm2.rs: same against `tpm2-pkcs11/1.10+swtpm` (token `tpm` now `scratch = true`).
- tests/p11kit.rs `the_forwarder_subtracts_exactly_its_layer`: through p11-kit, advertise ==
  softhsm profile − p11-kit layer. **Found** the layer was missing the three
  `CKM_CONCATENATE_*` (added, hand-maintained, [run]); p11-kit reports version 1.1, not 0.26.
- tests/yubikey.rs `the_read_only_probe_conforms` (opt-in: `CAKEYS_TEST_YUBIKEY_MODULE` only,
  no credentials): `--diff ykcs11/2.7` → 0; `--write` → 17 (SO). **Found** ykcs11 reports
  "Yubico (<https://www.yubico.com>)" / 2.73 — the hand profile's match never matched; ykcs11/2.7 now
  carries the read-only rows from a probe of the YubiKey 5C NFC FIPS here (model "YubiKey
  YK5", firmware "5.74"), partial dropped; the unit test's Unknown case uses a synthetic
  partial profile. Ran green against the real device.
- Local runs: `bash <scratchpad>/testenv.sh up; . <scratchpad>/te/env` mirrors preCheck
  (p11-kit socket under /tmp/opencode/probe/p11 — sun_path limit). Locally the HMAC/KWP
  tests fail by design (cargo links the unpatched cryptoki and `*_REQUIRE` is set); only the
  Nix build is authoritative.

## Remaining

1. Nix: `nix build .#cakeys .#checks.x86_64-linux.profiles` with the new tests. Run 1 found
   the binding dependence: under the patched (Nix) cryptoki kryoptic also advertises
   `CKM_AES_KEY_WRAP_KWP`, which unpatched cryptoki silently drops from
   `C_GetMechanismList`. Fixed: `probe --out/--diff` refuse (17) under an unpatched binding;
   the conformance tests skip there (gated like the HMAC tests); all profiles regenerated
   with a check-less Nix build (`nix build --impure --expr '(…cakeys).overrideAttrs (_:
   { doCheck = false; })'`); the YubiKey diff step skips under cargo (unpatched) and
   conforms with the Nix binary. Run 2 passed (all live suites). Then `checks.formatting`
   found taplo reflowing the generated profiles' long arrays (would break byte-identity after
   `nix fmt`): the emitter now lays arrays out as taplo does (`toml_array`, pinned by
   `arrays_are_laid_out_as_the_formatter_would`); profiles regenerated; `nix fmt` changes
   nothing. Also fixed a pre-existing typos failure (a commit hash in PROVIDERS.md): typos
   ignores hex hashes (treefmt.nix). Run 3 passed: cakeys (live suites), profiles,
   formatting, clippy, lib, fuzz, deny.
2. **Committed 45db101** "PROVIDERS phase 3: the probe, generated profiles and conformance"
   (WORK.md left out). Next per the ground rules: D8 and the `--config`-required CLI
   restructuring (deferred until after phase 3). Old note:
   `git mv`; the new sources are intent-to-add.
3. Docs done: PROVIDERS.md (probe section wording, D9/D10 revised, phase row, "Phase 3
   results", Tests), CONFIG.md (`scratch`; the real-TPM example no longer applies swtpm).

## Local probe scratch setups (/tmp/opencode/probe/)

- softhsm: `SOFTHSM2_CONF=/tmp/opencode/probe/softhsm2.conf`, token `kmprobe`, PIN 1234,
  config `/tmp/opencode/probe/keys.toml` (token `p`).
- kryptic 1.5.4 (the flake's version — must be this, not registry 1.5.3):
  `/nix/store/nj6mqmblcr6gnqn3nfpk3l4d4ricc9hv-kryoptic-1.5.4/lib/libkryoptic_pkcs11.so`,
  `KRYOPTIC_CONF=/tmp/opencode/probe/kryoptic.conf`, config `kryptic-keys.toml` (token `k`).
- tpm2: env via `. /tmp/opencode/probe/tpm/env` (from nix/tpm2-test-env.sh up), module
  `/nix/store/m6zgyxmd254bmw4pi6g9wz8p9j5g1qvq-tpm2-pkcs11-1.10.1/lib/libtpm2_pkcs11.so`,
  config `tpm-keys.toml` (token `t`; `--diff tpm2-pkcs11/1.10+swtpm`).
- cargo/nix commands run through `nix develop -c bash -c '...'` (no cargo on plain PATH;
  python3/perl unavailable — inspect bytes with od/hexdump).
- Embedded profiles mean every committed-profile change requires a rebuild before
  diff/conformance reflects it (`include_str!`).

## Probe findings worth preserving

- SoftHSM: generates all 6 Weierstrass + edwards25519/edwards448 curves, RSA 1024–4096,
  OAEP SHA-1 only (SHA-256 wrap = CKR_ARGUMENTS_BAD), refuses CKA_VALUE_LEN in unwrap
  templates (CKR_ATTRIBUTE_READ_ONLY). (Its "refusal" of CKA_WRAP/CKA_UNWRAP in pair-gen was
  the probe putting CKA_WRAP on the private template — CKR_ATTRIBUTE_TYPE_INVALID is correct.)
- kryptic: advertises the full PKCS#11 3.2 PQ surface (CKM_ML_DSA/ML_KEM/SLH_DSA + Hash*
  variants); OAEP SHA-1 and SHA-256 both round-trip, CKA_VALUE_LEN accepted in unwrap
  templates; secp256k1/brainpool = CKR_GENERAL_ERROR. (The earlier "OAEP fails both handles"
  was a probe bug — and contradicted MIGRATE.md:41's spike evidence, which should have been
  the cross-check: a probe result that disagrees with [run] evidence is a probe suspect.)
- tpm2-pkcs11: secp256k1/brainpool/edwards refused, RSA capped at 3072 (4096 =
  CKR_ATTRIBUTE_VALUE_INVALID), no AES/secret keygen in-session (needs tpm2_ptool), module
  reports Cryptoki 2.40, token model NUL-padded fixed-width field.
- cryptoki's `generate_key_pair` returns **(public, private)** — easy to get backwards.
- TOML pitfall recurring in tests: top-level keys after a table header become subkeys of
  that table.

## After phase 3 (2026-11-13, committed 77678d7)

- docs/USE_CASE.md: problems 6 (token conformity: `probe --diff`) and 7 (FIPS mode before
  use, *planned*); the Nix problems renumbered 8–12.
- docs/PROVIDERS.md D12 (user-agreed): token mode as match *fields*, not logic —
  `[match.fields]` in the one schema, vendor fields provider-prefixed, reported by an
  observe-only provider hook plus the standard 3.2 sources; generic equality matching, absent =
  any, most-matching wins, mismatch → advertise-only. `tokens.<t>.require` checked against the
  live token at open, refused with 14. Phase 5 row added (independent of phase 4).
