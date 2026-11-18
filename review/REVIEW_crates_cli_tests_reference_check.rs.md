# Review: crates/cli/tests/reference/check.rs (252 lines)

Reviewed 2026-11-18 [read]. Summary: `check`'s own behaviour: the pkcs11-provider key file
(verified end to end through OpenSSL), the URI's module and PIN parameters, a scheme the token
cannot compute, `check --token` over a whole token (0, 20, 17), and the `--at`/`--ignore-validity`
flags of the B8 fix. The PEM test is excellent: it checks the key file through an independent
consumer. The B8 test cannot see whether the flags reach the attestation.

## Findings

### F1. `check_judges_attestation_dates_at_the_time_asked` never reaches an attestation — risk

**Verification:** confirmed (test gap, already acknowledged). reference/check.rs:238-251 creates a plain EC key, so `--at`/`--ignore-validity` returning 0 says nothing about `ChainTime` reaching `AttestCtx` (crates/cli/src/lib.rs:144-149, :219-221 → crates/ykcs11/src/lib.rs:200-202); no other test in crates/*/tests passes `--at`. ISSUES.md:138-139 (B8, "Done") states the CLI route was tested only "on a key without attestation", so the gap is disclosed but not tracked as open. [read]
`reference/check.rs:236-252`. The key is a plain SoftHSM EC key with no attestation, so
`--at 2030-01-01T00:00:00Z` → 0 and `--ignore-validity` → 0 hold whether or not the time ever
reaches `AttestCtx`/`ChainTime`. Only the parse error (17), the note text and the clap conflict
are actually tested. docs/CAKEYS.md cites this test as the evidence for `check --at`, and ISSUES.md
B8 ("Done 2026-11-17") says the CLI route was tested "on a key without attestation". No other test
in the repository passes `--at` (search of `crates/*/tests`). Failure scenario: a refactor drops
`chain_time` from the context `check` builds (it defaults to the clock), and every test stays
green. Fix: `reference/proofs.rs:386-441` already plants ykcs11's fixture chain on this token under
`provider = "ykcs11"`. Add `check --at <before the slot certificate's notBefore>` there, expecting
the date refusal rather than the root refusal, and `--ignore-validity` falling through to "no
pinned root" (13). [read]

### F2. A clap conflict is asserted as "not zero" plus clap's prose — practice

`reference/check.rs:249-251`. `assert_ne!(code, 0)` would also accept a crash or 17. "cannot be
used with" is clap's wording, not cakeys'. Exit 2 is the documented usage code (docs/CAKEYS.md):
assert `== 2` and drop the prose. [read]

### F3. `pinEnv` is never turned into `pin-source=env:` — practice

`reference/check.rs:56-60` tests `--uri-pin source` only with `pinFile` (`file:`). docs/CAKEYS.md
("The contract with programs") documents `env:` for `pinEnv`, and no test covers it
(`reference/tokens.rs:35` uses `pinEnv` only for the unset-variable refusal). [read]

### F4. Incidental prose pinned — nit

`reference/check.rs:219` (`"2 of 3 on token 'ref'"`) and `:150` (`"implements none of
CKM_AES_CMAC"`) pin message wording on top of the frozen exit codes. Acceptable where the message
is the contract (the per-object `exit NN:` prefix at `:216-217` is); these two are not. [read]

### F5. The hidden-mechanism configuration is built inline — nit

`reference/check.rs:104-107` duplicates `Env::hiding` (`reference/mod.rs:130-135`). [read]

## Design

- The B8 fix is security-relevant (an expired attestation chain must fail `check`), and its only
  CLI test cannot fail on the property it is named for. The provider-level test
  (`check_holds_the_chain_to_its_dates` in ykcs11) covers the chain logic, but nothing covers the
  plumbing.

## Checked, no issue

- `check_pem_is_a_key_file_for_pkcs11_provider`: the key file's public key must hash to the locked
  `rfc7093m4`, OpenSSL signs through both `pin-source` and `pin-value`, and the signature verifies
  with OpenSSL alone. The `CKA_ID` warning and the 15/17 refusals are covered.
- `check_token_checks_every_object_on_it`: 0 with the module path, 20 with empty stdout and one
  line per failure with its own code, and every documented 17 case.
- `scheme_the_token_lacks_is_refused_before_create`: the observation proves the hidden
  configuration was the one loaded (`:134-138`), so the 15 is not a coincidence.
