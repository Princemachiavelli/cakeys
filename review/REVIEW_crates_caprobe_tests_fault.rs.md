# Review: crates/caprobe/tests/fault.rs (227 lines)

Reviewed 2026-11-18 [read]. Summary: `caprobe probe --write` on SoftHSM behind the p11-fault
shim, under ten fault plans (refused usage, a dropped point, another key signing or deriving,
refused sealed derivation, a busy session, wrap without unwrap...), the five `derive_any`
template fallbacks, a drift against the committed profile (15), and the clean-up of a stale
probe object. Each case checks exit 0, that a rule fired, and that given substrings appear in
the profile or the notes. The positive checks are solid; the file's stated guarantee ("never
the row a well-behaved module would have earned") is not asserted.

## Findings

### F1. Most cases never check that the earned-if-honest row is absent — risk

**Verification:** confirmed (downgraded to practice). `probe_cases` (`fault.rs:58-67`) has only presence checks, so the doc's "never the row a well-behaved module would have earned" (`:70-72`) is unasserted for eight cases; but the named regression ("notes the lie and still writes the row yes") is structurally blocked for the operation probes: `Ops::record` (`crates/caprobe/src/probe.rs:386-396`) puts one outcome in exactly one of worked/busy/failed, and the note is written from `failed` (`:398-420`), so a noted failure cannot also count as worked. Negative assertions would still guard the derive/notes paths that are coded separately. [read]
`crates/caprobe/tests/fault.rs:56-68`, `:70-156`. `probe_cases` asserts only that expected
strings are *present*. The doc comment (`:70-72`) promises "never the row a well-behaved module
would have earned". Two cases pin the row's `answer = "no"` (`:114-117` for
`derive.ecdh.sealed`, `:150-153` for both `wrap.rsa-oaep.*` rows); the other eight assert a note
or nothing about the row: "another key signs" (`:96-100`) checks the note "the signature does not
verify", not that the ECDSA operation row for secp256r1 is not `yes`; likewise "another key
derives", "derives while reporting CKA_DERIVE false", "no derivation at all"; and "a public key
without its point", "usage refused at generation" and the two busy-session cases (`:82-94`,
`:135-146`) have no row assertions at all, only the undetermined note. A
regression where the probe notes the lie *and* still writes the row as `yes` passes. Fix: give
`Case` a list of strings that must not appear (or rows with their required answer), e.g.
`"sign.ecdsa.CKK_EC.secp256r1" = { answer = "yes"` must be absent, and check them in
`probe_cases`. [read]

### F2. `fired > 0` is weaker than camigrate's `fired == 1` — nit

`crates/caprobe/tests/fault.rs:62`. camigrate's fault test requires exactly one firing per
single-rule plan, which catches a rule that matches more calls than intended. Here `> 0`
accepts a `call`-less rule (e.g. `"no derivation at all"`, `:121-124`) matching every call, which
is intended there, but also a numbered rule landing on a different step than the comment says.
Fix: give each case its expected count (most are exactly the number of rules in its plan). [read]

### F3. Call numbers derived from the probe's internal order — nit

`crates/caprobe/tests/fault.rs:46-50`, `:97`, `:103`, `:111`, `:137`. `SIGN_INITS = 2` and
`DERIVES = 1` encode how many `C_SignInit`/`C_DeriveKey` calls the first key's proofs make before
the mechanism probes. A change to the proof order moves every numbered case; the substring
checks catch most moves, F1's negative checks would catch the rest. Documented in place, so
only noted. [read]

### F4. P-256 OID literal, another copy — nit

`crates/caprobe/tests/fault.rs:22`. See dry_run.rs F4: the same 10 bytes are in four other test
files; `common/mod.rs` has P-384/Edwards OIDs but no P-256 one. [read]

## Design

- Profile rows are asserted as TOML text fragments (`"\"derive.ecdh.sealed\" = { answer = \"no\",
  evidence = ..."`, `:115`, `:151`). That couples the test to the emitter's layout (ISSUES.md Q27)
  as well as its content; parsing `stdout` with `cakeys_profile` and asserting on the `Row` would
  separate the two.

## Checked, no issue

- Skip through `suite_var` with `CAKEYS_FAULT_REQUIRE` (set by `nix/test-tokens.sh:78`).
- ISSUES.md Q3 "Done": the busy-session cases match by `CKR_OPERATION_ACTIVE` as a return value
  (`:135-146`), and the expected note names the value, consistent with the claim that both
  cases fail without it.
- The drift case asserts exit 15 against `softhsm/2.7` and names the drifting row.
- The stale-object test asserts the note and that the object is gone on the real token.
- A missing trace reads as empty, so `fired > 0` fails when the shim is not loaded.
