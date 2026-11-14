# Next: round out the feature set (2026-11-13)

**Ordering:** [`WORKPLAN.md`](WORKPLAN.md) now sets the order of this work and replaces the
order below; this file remains the task list it draws on.

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
      generic skip note (`not_created`, crates/pkcs11/src/ops.rs).

## 2b. Hardware profiles (2026-11-13)

- [x] **YubiKey**: ykcs11/2.7 is probe output from a scratch slot (`scratchId`), with
      operation probes and `[manual]` findings; Ed25519 generation by name, `pop-ecdh` on
      ykcs11 and tpm2-pkcs11, P-384/Ed25519/RSA-2048/RSA-3072 hardware tests
      (docs/PROVIDERS.md, "Probe on hardware"). The test slots are retired 90–95.
- [x] **fTPM** (AMD Ryzen 7 5700G, firmware 3.87): `tpm2-pkcs11/1.10+amd-ftpm` is probe
      output (nix/ftpm-test-env.sh: tpm2-abrmd over /dev/tpmrm0, a fresh transient-parent
      store; tests/ftpm.rs, opt-in). Pairs of one module now resolve by their hardware, and
      tie with module rows only when no token says which.
- [ ] **tpm-certify on a real TPM**: needs a persistent primary and an Attestation Key; the
      test store's primary is transient on purpose. Decide where (which handle) before
      testing it on a TPM the platform uses.
- [ ] **X25519 / Montgomery keys**: no key type in id.rs (SPKI, host X25519); ykcs11 cannot
      generate them anyway ([manual.x25519]).
- [ ] **FIPS mode as a match field** (D12): ykcs11/2.7 was probed in approved mode, so it
      may refuse on a non-FIPS 5.7.4 what that device can do ([manual.fips-mode]).

## 2c. Replay (docs/REVIEW-2026-11-13.md, "Replay") — minor, maybe

Secret keys cannot be replay-safe in general: their IDs are fingerprints (`assurance =
"fingerprint"`, done), since a verifier with no secret cannot check a fresh answer. These narrow
the gap without closing it.

- [ ] **Maybe: `tpm-certify` for secret keys on a real TPM.** `TPM2_Certify` is nonce-bound,
      so a TPM-held secret key gets `assurance = "proof"` (the code already says so). It needs
      a persistent primary and an AK on the platform's TPM (see the tpm-certify item in 2b), and
      the AK proves "the same TPM", not "a genuine TPM", until the EK chain exists (A8).
- [ ] **Maybe: a challenge bank.** `realise` asks the token N random challenges, and each
      check asks one and compares its digest. Where the challenges live decides what it buys:
  - **In the lock:** public, so only probabilistic against an observer of past checks.
  - **On the token itself:** buys nothing. The token and every module on its path see the
    challenges and the answers, and nobody else could compute an answer without the key
    anyway, so a hidden input adds nothing over today's fixed one.
  - **Host-held and secret** (a sealed file, or sealed to the TPM), each challenge used once:
    defends against a module, forwarder or token compromised *after* `realise`, until the bank
    runs out. It needs mutable host state (consumption), which the sandboxed `check` does not
    have, and it never helps against a token that was already malicious at `realise`, since it
    answered every challenge then.

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
