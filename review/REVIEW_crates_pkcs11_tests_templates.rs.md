# Review: crates/pkcs11/tests/templates.rs (183 lines)

Reviewed 2026-11-18 [read]. Summary: `Provider::template` on SoftHSM, in-process: a recording
provider sees both halves of a generation, a proof's sealed session secret and the host KEK
asked, its `CKA_SUBJECT` stamp reaches the token, and its refusal leaves nothing under the
locator; a provider refusing the proof's session secret makes `ops::create` fail before
generating. Direct and useful; its skip ignores the REQUIRE convention and one assertion uses
the notes as a stand-in for "nothing was generated".

## Findings

### F1. The skip ignores `CAKEYS_TEST_REQUIRE` — risk

**Verification:** confirmed (downgraded to practice). `token()` (`templates.rs:75-79`) does skip on a bare `std::env::var` without the REQUIRE check; but `CAKEYS_TEST_MODULE` comes from the same single export that sets `CAKEYS_TEST_REQUIRE=1` for the whole check phase (`nix/package-common.nix:178-179`; `scripts/local-tests.sh:107`), so dropping the module there would also fail every `suite_var` SoftHSM suite. "No gate noticing" does not hold; the inconsistency with the convention does. [read]
`crates/pkcs11/tests/templates.rs:75-79`. `token()` reads `CAKEYS_TEST_MODULE` with
`std::env::var` and returns `None` with a stderr line, where every other token suite uses
`common::suite_var`, which fails when the module is missing and `CAKEYS_TEST_REQUIRE` is set
(`crates/cli/tests/common/mod.rs:49-56`). If a change to the check phase stopped passing the
module to this crate's tests, both tests would turn into silent passes with no gate noticing.
Fix: include `common` (as the camigrate/caprobe tests do via `#[path]`) and use
`suite_var(SOFTHSM.module_var, SOFTHSM.require_var, ..)`, or check the REQUIRE variable here.
[read]

**Fixed (2026-11-18):** `token()` fails when `CAKEYS_TEST_REQUIRE` is set and the module is not (verified FIXED)..

### F2. "Never generated" is inferred from the notes being empty — practice

`crates/pkcs11/tests/templates.rs:129-133`. The claim is that the refused proof template is asked
before the key is generated. `notes.lines() == []` stands in for "not generated and removed
again", relying on the rollback writing a note; any unrelated note `create` adds later (a
profile note, a by-name curve note) fails this test for the wrong reason, and a rollback that
stops noting itself makes it pass even if a key was generated and removed. The `find_any == 0`
check that follows cannot tell the two apart on SoftHSM (it deletes). Fix: have `NoProof`
record the `Template::Generate` requests (like `Stamp`) and assert none was asked, which is the
ordering the comment describes. [read]

**Fixed (2026-11-18):** `NoProof` records each template; the generation's are asked once (by the check) and the refused proof secret is the last asked. Test: `a_refused_proof_template_creates_nothing` (not run: the workspace did not build during the run).

### F3. Four template kinds are recorded but never exercised — nit

`crates/pkcs11/tests/templates.rs:49-52`. `Stamp` names `Import`, `PublicHalf`, `Object` and
`TrustedCopy`, but the test asks only for generation, a proof secret and the host KEK. The header
scopes it that way; the other four hooks are reached only through camigrate/caprobe runs with
the default providers, which never refuse or change anything, so a path that skipped the hook for
an import would go unnoticed (the gap `caprobe/tests/template_hook.rs` closes for the probe's
secret keys only). [read]

**Fixed (2026-11-18):** the trusted copy is made as SO through `create_trusted_copy`, its template asked and the provider's `CKA_ID` read back; Import/PublicHalf/Object are asserted in caprobe's template_hook.rs (camigrate's own asks stay untested in-process: no registry-injectable entry point). Test: `templates_pass_through_the_provider` (not run).

## Design

- Both this file and `caprobe/tests/template_hook.rs` define a test provider by hand
  (`matches` false, `template` refusing one kind). A small configurable test provider
  (refuse/record by `Template` variant) in a test-support module of `cakeys-pkcs11` would let
  each verb's hook use be tested the same way.

## Checked, no issue

- `Set::activate_embedded()` (ISSUES.md Q24) is the repeatable activation, called before the
  skip; both tests in one process are fine with it.
- Each test destroys its locators before creating, and the labels are distinct, so the two tests
  share the token safely under `cargo test`'s threads.
- `taken()` drains the recorder between steps, so each assertion sees only that step's requests;
  the host-KEK step asserts the exact list.
