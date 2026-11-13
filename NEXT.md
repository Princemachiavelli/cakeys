# Next: round out the feature set (2026-11-13)

Decided with the user after PROVIDERS phase 3 (45db101): finish the work in progress, then
refine and add test coverage. "Feature-complete" is everything through MIGRATE phase 5; native
TPM duplication (MIGRATE 6), vendor methods (MIGRATE 7) and the items PLAN.md parks (native TPM
backend, post-quantum, lock merge, keystores, the attestation remainders) stay parked.

## 1. Cleanups (≈2 days)

- [x] **Commands that need no keys.toml stop requiring `--config`** (`supports`, `probe` with
      `--module`, …) — deferred from PROVIDERS phase 1. Done: only `supports --profile` qualifies
      (`probe` needs the token's config); others exit 2 naming `--config`.
- [x] **PROVIDERS phase 4**: the static `validate` gate (each spec's demands against its
      token's effective profile, no token attached) and the wider Nix check.
- [x] **M1/M2** (0ea445e): read-only sessions for read-only verbs; read the PIV PIN counters
      (`CKF_USER_PIN_FINAL_TRY` …) before login.
- [ ] **D5**: at token open, a read-only check of the live token against its resolved
      profile (`diff::read_only`), as a note — possible since phase 3.
- [x] **Probe leftovers**: a killed run's `cakeys-probe-NN` objects are found before probing
      (refused or cleaned), never reported as a delete failure.
- [ ] **Minor (review 2026-11-13): the profile set is parsed per token open.**
      `resolution::resolve` re-parses the embedded profiles (`Set::embedded()`) on every token
      open, so `create` over several tokens parses them once per token: parse once per process
      (`OnceLock`). (`Token::open`'s slot search is extracted: `find_slot`, `module_info`.)
- [ ] **Minor (review 2026-11-13): the token suites crash when run in parallel.** Plain
      `cargo test` with the token env vars set runs the suite's tests on several threads, each
      opening its own `TestSession` on the same module in the test process: one finalizes the
      module under the others (SIGSEGV seen with SoftHSM). The Nix build runs them on one thread
      (`dontUseCargoParallelTests`). Fix: one process-wide session per module in
      `tests/common`, or a lock around `open_session`; until then, pass `--test-threads=1`.

## 2. Migration (MIGRATE.md phases 2–5)

- [ ] **Phase 2** `public`: certificates, public keys, data objects.
- [ ] **Phase 3** `sealed`: the `transport` verb, RSA-OAEP + AES-KWP and direct OAEP, bundles,
      import with identity check and cleanup, `migrate`. Consumes the profiles' `wrap.oaep` and
      `unwrap.refuse`. **D8** (the lock records the resolved profile name) lands in the same lock
      change as MIGRATE D7's `origin`, so the draft lock format changes once.
- [ ] **Phase 4** `host`: `--allow-host-plaintext`, zeroized buffers, `tpm2_ptool` import.
- [ ] **Phase 5** YubiKey import through ykcs11 as SO (the hardware test overwrites scratch slot
      0x95: ask before running).
- [ ] **Multi-token objects: one creation token** (2026-11-13). An object whose specs name
      several tokens has no rule for *where* it is born: `cakeys create` takes config order and
      `autoCreate` whichever pair runs first, and every other token can then only adopt the same
      material. Let keys.toml name the creation token (or provider) per object, so `create` and
      `autoCreate` generate only there — `autoCreate` on another token is invalid (17) — and the
      other tokens adopt it: through cakeys' `export`/`migrate` (phase 3) or any outside tool
      (`pkcs11-tool`, `ykman`, `tpm2_ptool`), checked against the locked identity either way.
      Then `create` can say "import from <creation token>" for those tokens instead of today's
      generic skip note (`not_created`, crates/cli/src/lib.rs).

## 3. PROVIDERS phase 5 (D12)

- [ ] `[match.fields]`, the standard 3.2 fields, the observing provider hook (ykcs11 FIPS mode
      on the YubiKey 5C NFC FIPS here, the TPM's `TPM_PT_MODES`), `tokens.<t>.require` (14).

## 4. Refine and cover (docs/VERIFICATION.md's next steps)

- [ ] Measure first: line coverage (`cargo-llvm-cov`) and mutation testing (`cargo-mutants`)
      in Nix, so new tests go where the gaps are.
- [ ] Fuzz the unfuzzed parsers: the PIV chain, `TPMS_ATTEST`, the P-521 fix-up, profile
      emit/parse round trips.
- [ ] Kani on the parsers; a Quint model of the lock rules.

## Already done right

- The PIN and the admin credential are held in `Zeroizing` and wiped after use.
- Randomness comes from the OS RNG (`getrandom`, `sys_rng`).
- The RustCrypto crates are built with `default-features = false` and only the features needed.
- Public keys are re-encoded canonically before hashing, so module encoding quirks never change
  an identity.
- The ECDSA hash comes from the signature algorithm (prehash), not from the curve.
- `Cargo.lock` is committed, and every dependency is on its latest release (DESIGN §6.4).
