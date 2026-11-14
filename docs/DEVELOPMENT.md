# Development

How to build, test and change cakeys, and the rules that protect the hardware attached to the
development machine.

## Environment and the checks

The OS is NixOS: there is no system `cargo`, `python3` or `perl`.

- Build and test with `nix develop -c cargo …`; any other tool with `nix shell nixpkgs#<name> -c …`.
  Use `rg`, not `grep`; shell scripts start with `#!/usr/bin/env bash`.
- Format with `nix fmt -- --no-cache` (the cache has missed files before).
- **Per change:** `nix develop -c cargo clippy --workspace --all-targets -- -D warnings` and the
  unit tests. Clippy is pedantic: a function that can panic needs a `# Panics` section, and
  exemptions are per-site `#[expect(lint, reason = "…")]`.
- **After a significant change:** `nix build .#checks-crane-only`, every check except the fuzz
  smoke run, on the crane build (its dependencies cached per `Cargo.lock`).
- **At the end of a piece of work:** `nix flake check`, all checks passing.
- The token suites (SoftHSM, kryoptic, p11-kit, swtpm) run only in the Nix build's check phase;
  under plain `cargo test` they skip. A change to token behaviour is not tested until a Nix check
  has run.
- `nix flake check` sees only files git knows: `git add` new files first.
- `packages.cakeys` is the regular `buildRustPackage` build, `packages.cakeys-crane` the crane
  build the checks use; `nix/package-common.nix` holds what they share.
- Generated profiles must stay byte-identical to the committed ones, and only the Nix-built
  binary carries the patched cryptoki the probe needs: `scripts/regen-profiles.sh` gives the
  commands. The baseline is regenerated with `CAKEYS_UPDATE_BASELINE=1`, then `nix fmt`.
- Port 23211 on the development machine belongs to another process's swtpm: pass another port
  (`TPM_PORT`, or the third argument of `nix/tpm2-test-env.sh`).

**Frozen names.** Scheme names, method names, exposure levels, the bundle format and exit codes
are pinned by tests (`scheme_definitions_are_pinned`, `method_names_are_pinned_and_round_trip`,
`spec_digests_are_pinned`). If one of those fails, the change is wrong, not the test.

**Git.** Work on a branch; the user decides what is pushed and merged. Match the surrounding
code's style and comment density.

## Hardware rules

Two real devices are attached to the development machine, and both hold things the user depends
on. These rules have no exceptions; if a task cannot be done within them, stop and report.

**The TPM (AMD fTPM, firmware 3.87).** It unlocks the disk and backs secure boot.

- Never run `tpm2_clear`, change a hierarchy auth, use the lockout auth, extend a PCR, or
  define, write or undefine NV indices.
- Never evict or change the persistent handles `0x81000001`, `0x81000002` and `0x81010001`.
  Record `tpm2_getcap handles-persistent` before and after any TPM work and compare.
- Never send a wrong PIN or auth value. The dictionary-attack counter is shared with disk
  unlock; check `TPM2_PT_LOCKOUT_COUNTER` is still 0 afterwards.
- Reach the TPM through `nix/ftpm-test-env.sh` (tpm2-abrmd over `/dev/tpmrm0`), never
  `/dev/tpm0`.
- The one persistent object cakeys made is its Attestation Key at `0x81000016` (2026-11-14);
  `tpm2_evictcontrol -C o -c 0x81000016` removes it.

**The YubiKey (5C NFC FIPS, firmware 5.7.4).**

- Slots 82, 83 and 84 hold the user's keys. Never write to them, never generate, import or
  delete there, and do not run a proof of possession on them. `examples/yubikey-secureboot.*`
  describes those keys: do not `realise` it against the device.
- Test keys go in retired slots 90–95 only (`CKA_ID` 13–18). The scratch slot for write probes
  is `scratchId = "17"`; camigrate's import test uses slot 95 (ask before running it).
- The credentials are files in `/data/srcs/waste/yubikey_data`: `PIN.txt` is the PIN and
  `piv_mnmgt_key.current.txt` the management key. Pass them as file paths (`pinFile`,
  `mgmKeyFile`). Never print them, copy them into the repository, or put them in a commit, a
  log or a report.
- The PIN has 3 tries. Never guess; if a login fails once, stop.

## Testing

| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | digests (pinned), curves and OIDs, SPKI round-trips, registry, P-521 fix-up, hex parsing, proof-of-possession host math (both ECDH MAC sides), the signature verifiers, the deprecation register and scheme names, AES strength order, the observed policy vectors, the attestation scheme definitions and lock invariants, the lock rules (first use, what a write may override, attestation changes, provenance warnings), the PIV chain verifier (fixture chain + Yubico's own roots and intermediates) |
| `crates/core/tests/properties.rs` | `cargo test --workspace` | proptest: recording then comparing passes and a second write changes nothing; after a recorded realisation, another material is 10 and a weaker binding or replaced object 14 in both modes, drift fails only a compare, and a successful write never overwrites a locked ID; material links only through a shared scheme (disjoint 14, other material 10, else gaps filled); the attestation and commitment-label encodings are injective; `sri`/`is_sri` agree; key and certificate parsers and the loaders never panic. Mutation-checked: disabling the binding-downgrade or the shared-scheme rule fails it |
| `checks.fuzz`, `apps.fuzz` | package build / host | cargo-fuzz targets (`fuzz/`: the key and certificate parsers, the lock and config loaders, the bundle, and tpm2-pkcs11's store rows and `TPMS_ATTEST`) on the stable rustc (`RUSTC_BOOTSTRAP=1`, no sanitizer, debug assertions): the check runs 100 000 inputs per target from a fixed seed and the fixtures; `nix run .#fuzz -- <target> [libFuzzer flags]` runs one as long as wanted |
| `tests/softhsm.rs`, `tests/kryoptic.rs` | package build | one shared suite (`tests/reference/`) against each software reference: lifecycle, every type and scheme against independent oracles (hand-written DER encoder, openssl-hashed fixtures, RustCrypto `hmac`/`cmac`/`aes`/`aes-kw`); the same verdicts on both, with each token's facts in its `Reference` descriptor (`tests/common/`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm + tpm2-abrmd + tpm2-pkcs11; the native `tpm-certify` attestation (AK provisioning and validation, reads that never provision, a lost attestation as a downgrade, cross-checks), one material attested on two tokens with an attestation each, and the travel of attested material to SoftHSM through the shared portable scheme |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access |
| `tests/references.rs` | package build | cross-reference: the same material (the P-256 and RSA fixtures, P-384/P-521/Ed25519/Ed448 exported from one reference, AES, generic secret and HMAC values, a certificate, a data object) planted on SoftHSM, kryoptic (raw and DER Edwards points), SoftHSM behind p11-kit and — what `tpm2_ptool` imports — tpm2-pkcs11, realised into one lock: one identity per scheme everywhere; and the same verdict for the same scenario (absent 11, two objects 12, another type 13, a swapped private key 13) |
| `crates/camigrate/tests/dry_run.rs` | package build | the dry-run property: for every source and target reference and the types each takes, the plan's verdict is the outcome, a ready move is recorded with its `origin` and verified by `cakeys`; the bundle, key files, `enforced` and host paths, and each refusal's exit code |
| `tests/yubikey.rs` | opt-in, never in the Nix build (`CAKEYS_TEST_YUBIKEY_MODULE`, `_PIN`, `_MGM` — file paths; the secrets are only ever read from them) | a real YubiKey, read-write: generate into the scratch PIV slot `0x95` in an SO step, then (back as the user) attest it and prove possession by signing, record, verify; `delete` refused (15) with the realisation kept; re-realise idempotent — each CLI run bounded, so a touch or PIN prompt fails instead of waiting (`rw_lifecycle_generates_attests_proves_and_refuses_delete_without_touch`) |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | the CLI flow; in the VM also the pseudo-FOD consumer built in the guest sandbox |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | module, hook, pcscd, TPM ACL, Nix library |
| `checks.minimal` | package build | the CLI without its `tpm2`/`ykcs11` features builds without tpm2-tss and sqlite |
| `checks.formatting` | treefmt | `nix fmt` would change nothing: the formatters and linters in `treefmt.nix` (rustfmt with `rustfmt.toml`, nixfmt, taplo, shfmt, rumdl, keep-sorted, statix, deadnix, shellcheck, typos) |
| `scripts/xversion.sh` | by hand, per refactor | a lock recorded by one build verifies, compares and re-records byte-identically with another (every class) |

`tests/yubikey.rs` and the camigrate YubiKey import (`crates/camigrate/tests/yubikey.rs`) are
opt-in, as is the real-TPM attestation test (`CAKEYS_FTPM_ATTEST=1`, through
`nix/ftpm-test-env.sh`). `packages.test-nspawn` needs the `uid-range` feature, so it is outside
`checks`.

## Verification beyond tests

Bugs so far came from three places: the design (an identity taken from an unbound public
object, a forged `CKA_PUBLIC_KEY_INFO` accepted, a per-device attestation stored per object),
module and binding behaviour (ykcs11's delete, tpm2-pkcs11's P-521 point, cryptoki's HMAC
constants, p11-kit's dropped mechanisms), and very few from the pure logic. Only tests against
real modules catch the second kind; a proof of the Rust code would target the kind with the
fewest bugs. So the order is: the reference tokens and cross-reference tests (done), proptest
and cargo-fuzz (done), then models of the design — Quint or TLA+ for the lock rules, Alloy for
the lock's structure and its merge rule, Tamarin for proof of possession and attestation — and
Kani harnesses for small pure functions ([OPEN.md](OPEN.md)). Verus or Aeneas only for a
carved-out kernel, after a model says what it must satisfy.
