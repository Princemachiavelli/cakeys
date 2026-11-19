# Review: crates/caprobe/tests/reference.rs (203 lines)

Reviewed 2026-11-18 [read]. Summary: caprobe on the software references: the committed SoftHSM
and kryoptic profiles conform to a fresh probe byte for byte (`assert_profile_conforms`), a
diff against the other reference's profile is 15, write probes are refused on a non-scratch
token; p11-kit's `caps` and probe show exactly the layer profile's subtraction; and the
scratch-slot guard for SO-only providers, run on SoftHSM/kryoptic named as `ykcs11`. Strong
tests, with exact set comparisons and byte equality. One guard claim is asserted only by exit
code.

## Findings

### F1. "Never overwritten" is asserted by the exit code alone — practice

`crates/caprobe/tests/reference.rs:117-122`, `:183`. The doc comment says a slot holding anything
but ykcs11's placeholder "is never overwritten (17)". The test plants a certificate in slot 06
and asserts the probe exits 17 with the message, not that the certificate is still there, unchanged,
afterwards. A probe that destroyed or replaced the slot's objects and then reported the refusal
would pass. This is the guard that protects a real YubiKey's slots, so the stronger check is
cheap insurance. Fix: after `refused("taken", ...)`, find objects with `CKA_ID = 06` and assert
the one certificate with the fixture's value remains. [read]

**Fixed (2026-11-18):** after the refusal the slot 06 objects are read back: the one certificate, its fixture value. Test: `softhsm_the_scratch_guard_names_one_slot` (not run).

### F2. Two refusals assert the code without the output in the message — nit

`crates/caprobe/tests/reference.rs:31-32`, `:80`, `:102-103`, `:111-112`. `assert_eq!(code(&anon), 17)`
and the bare `assert!(stderr(..).contains(..))` print nothing useful on failure, unlike the rest
of the file. Add `"{}", stderr(&o)`. [read]

**Fixed (2026-11-18):** the assertions carry stderr..

### F3. Two write probes on one token in one test — nit

`crates/caprobe/tests/reference.rs:184-192`. `empty` and `placeholder` both run `probe --write` on
the same SoftHSM/kryoptic token. `common::assert_profile_conforms` warns that a second write
probe sees what the first left on modules that cannot destroy everything; harmless on these two
modules, and only `exit 0` and the scratch-slot note are asserted, so it cannot mislead today. [read]

**Decided (2026-11-18):** both modules destroy what the probe makes and each probe is in its own slot; a comment says so..

## Design

- The conformance check covers SoftHSM, kryoptic (here), swtpm (`tpm2.rs`) and the AMD fTPM
  (opt-in `ftpm.rs`); ykcs11, kmsp11 and aws-cloudhsm profiles are held only to the emitter
  (`crates/caprobe/src/emit.rs:236`, `every_committed_profile_is_what_the_emitter_writes`), not to
  any probe, and `caprobe/tests/yubikey.rs` probes read-only. That matches ISSUES.md Q28's claim
  (emitter, byte for byte) and the hardware rules; it means those profiles' contents are only as
  current as their last manual re-probe.

## Checked, no issue

- Skips use `suite_var` with each reference's REQUIRE variable, and the HMAC-fix skip uses the
  same REQUIRE: no silent skip in the gated runs.
- `the_forwarder_subtracts_exactly_its_layer` compares sets (forwarded == module − layer), checks
  the layer is a subset of the module's list, and pins the forwarder's identity; `--name` checked.
- `p11kit_forwards_a_filtered_view` compares array elements exactly (`any(|x| x == m)`).
- docs/CAPROBE.md:24-30: `probe --diff` drift is 15 (`:28`) and a write probe on a token not
  marked scratch is 17 (`:31`), both asserted.
- The scratch guard covers no slot, no admin credential, a user-creating provider with
  `scratchId`, no PIN, a foreign object, an empty slot and the placeholder.
