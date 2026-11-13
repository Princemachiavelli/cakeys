# Verification strategy (2026-11-12)

How to gain confidence in cakeys' own logic and design — not in the crypto crates or other
dependencies, which are trusted as they are. Tool availability is checked against the flake's
pinned nixpkgs.

## Where the bugs have come from

The review registers (`docs/REVIEW-2026-11-11.md`, `ISSUES.md`) show three kinds:

| Kind | Examples | What catches it |
|---|---|---|
| Design | H1 (identity from an unbound public object), H1b (forged `CKA_PUBLIC_KEY_INFO` passed), the per-device attestation ID stored per object, an attestation opt-out not treated as a downgrade | a model of the design (model checking, protocol proofs) |
| Token and library behaviour | ykcs11's delete leaves the key; tpm2-pkcs11's P-521 `CKA_EC_POINT`; cryptoki's HMAC key-type constants; p11-kit drops mechanisms | only tests against real modules |
| Pure logic (`reconcile`, `plan`) | few or none found | unit tests today; property tests and proofs |

A proof of the Rust code would target the kind with the fewest bugs, and it can say nothing about
the second kind: it proves our logic against a *model* of the token, and real modules depart from
what the specification promises.

## Tools

| Tool | What it is | Fit for cakeys | nixpkgs |
|---|---|---|---|
| Verus | SMT-based proofs; code written in its `verus!` dialect, limited std | Poor today: `reconcile`, `plan` and `config` are built on `BTreeMap<String, …>`, serde, toml and error enums. It would mean a second, rewritten kernel kept in sync with the real one | no (own pinned toolchain) |
| Aeneas (Charon → Lean) | Rust translated to Lean; proofs in Lean | Best on small pure functions (used for ML-KEM). Our candidates are tiny (the length-prefixed attestation encoding), and their sha2/serde calls would be axioms. High proof effort | no (lean4 4.35 yes) |
| Creusot | Contracts on ordinary Rust, proved with Why3 | Closer to normal Rust than Verus, same std/serde problem; pinned nightly | no (why3 1.8 yes) |
| hex | Rust → F\*/Lean for crypto code | Built for crypto implementations; cakeys has none of its own | no |
| Kani | Bounded model checker on unmodified Rust | The cheapest real proofs: harnesses check functions over all inputs up to a bound. Strings and maps make it slow, so keep bounds small | no (cbmc 6.11 yes; Kani pins its own nightly) |
| Quint / TLA+ | State-machine model checking | Good fit for the lock rules (below) | quint 0.33, tlaplus 1.8 |
| Alloy 6 | Relational models | Good fit for the lock's structure, and for the open merge rule (S16) | alloy6 6.2 |
| Tamarin / ProVerif | Security-protocol provers against an active attacker | Good fit for proof of possession and attestation: they prove the design, not a crypto library | tamarin-prover 1.12, proverif 2.05 |
| proptest / cargo-fuzz | Property-based tests and fuzzing | Highest value per hour on the core crate's rules and on everything that parses untrusted bytes | cargo-fuzz 0.13 (proptest is a crate) |

## What each would check

- **Quint (or TLA+), the lock rules.** Tokens and module as an adversary that can replace keys,
  swap objects and replay attestations; across every sequence of `realise`, `verify`, `delete`
  and `gc`:
  - a written lock never overwrites a locked ID, anchor, binding, type or immutable;
  - mode, binding, schemes and attestation never weaken;
  - material links only through a shared scheme;
  - the `<lock>.lck` sidecar keeps concurrent updates from being lost;
  - `gc` removes exactly the stale entries.
- **Alloy, the lock's structure.** One object per material, symmetric key ↔ certificate `pairs`,
  a realisation's `schemes` within its object's IDs, and lock fragments that split and join — the
  merge rule S16 still lacks.
- **Tamarin, the proofs and attestations.** A malicious module cannot make `verify` pass for a
  different key under `pop-sign`, `pop-ecdh` or `pop-decrypt`; `piv-attestation` can be replayed
  and `tpm-certify` cannot (both documented in DESIGN §8.2 as known; a model confirms or refutes
  them).
- **proptest, the core crate.** Recording is monotone; comparing right after recording passes;
  recording twice equals once; each refusal has its exit code; spec digests are stable under curve
  aliases; the attestation and commitment-label encodings are injective.
- **cargo-fuzz, untrusted bytes.** `spki_canonical`, `cert_spki` and the P-521 point fix-up; the
  PIV chain parser; `TPMS_ATTEST` and the TPM store blobs; the `keys.toml` and `keys.lock` loaders.

## Plan, in order

1. **Reference tokens and cross-reference tests (done 2026-11-12).** Add kryoptic as a third
   software reference beside SoftHSM and tpm2-pkcs11, run the shared suite on it, then test that
   behaviour is consistent across every reference: the same material gives the same IDs, the
   same scenario the same verdict, on SoftHSM, kryoptic, p11-kit and tpm2-pkcs11 where each
   supports it. This is the only defence against module behaviour.
   - Done: kryoptic runs the shared suite (`tests/reference/`, 46 tests on each software
     reference), and `tests/references.rs` plants the same material on SoftHSM, kryoptic (raw
     and DER Edwards points), SoftHSM behind p11-kit and tpm2-pkcs11, realises it into one lock
     and compares IDs and verdicts. A deliberately different HMAC value on one reference fails
     it, as it should.
2. **proptest and cargo-fuzz**, added alongside or after step 1. No new toolchain; runs in
   `nix flake check`. One to two days.
3. **A Quint model of the lock rules and an Alloy model of the lock structure**, including the
   merge rule (S16). A few days each.
4. **Tamarin models of proof of possession and attestation.** A few days of specialist work;
   worth it if the threat model should survive outside review.
5. **Kani harnesses** for small pure functions (encodings, ranks, scheme selection), once Kani
   is packaged as a flake input.
6. **Verus or Aeneas only for a carved-out kernel** (`reconcile` over abstract IDs, no serde or
   strings), and only after step 3 says what that kernel must satisfy.
