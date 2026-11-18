# Review: crates/profile/src/effective.rs (549 lines)

Reviewed 2026-11-18 [read]. Summary: the stack algebra (baseline, one module profile, delta
layers) that answers yes/no/unknown for mechanisms, generation, curves, classes and OAEP, each
verdict naming the profile that decided. Clear and well tested for the cases it tests; two
generation rules answer *yes* where the module's own rows do not support it, which goes against
the file's "unknown, never a guess" contract (D5).

## Findings

### F1. A key type whose every generate row says no answers *yes* when no curve or size is asked — bug

**Verification:** confirmed. `generation` returns `Some` once any row of the type exists (profile.rs:387, :403) and `generate` with no item and no bits falls through to `Verdict::yes` (effective.rs:219); `caprobe supports CKK_EC_EDWARDS --profile tpm2-pkcs11/1.10+swtpm`, whose only Edwards rows are two `no`s (profiles/modules/tpm2-pkcs11/1.10+swtpm.toml:62-63), printed `CKK_EC_EDWARDS: yes (tpm2-pkcs11/1.10+swtpm)`. [run]
`crates/profile/src/effective.rs:174` and `:219`, with `profile.rs:376-402`. `m.generation(kt)`
is `Some` as soon as any `generate.<kt>.*` row exists, whatever it answers; with `item` and `bits`
both `None`, `generate` falls through to `Verdict::yes(&m.profile, …)`. Committed example:
`tpm2-pkcs11/1.10+swtpm` has only `generate.CKK_EC_EDWARDS.edwards25519 = no` and
`…edwards448 = no`, so `caprobe supports CKK_EC_EDWARDS --profile tpm2-pkcs11/1.10+swtpm`
(`query` -> `generate(name, None, None)`) prints `yes (tpm2-pkcs11/1.10+swtpm)`. The same happens
for an RSA type with only `cannot_bits`, and (via `profile.rs:399`, which drops `Bytes` rows
after setting `any = true`) for a type with only secret-key-size rows. The gate is mostly
spared because EC/Edwards objects carry a curve and RSA a size, but the `supports` verb answers
wrong. Fix: with no item and no bits, answer yes only if some row of the type says yes (or the
module only reports a range), no if every row says no.
[read]

### F2. Size interpolation ignores a refused size between two that generated — risk

**Verification:** confirmed. effective.rs:191-196 takes only min/max of `can_bits`; `caprobe supports CKK_RSA --bits 2560` and `--bits 1280 --profile tpm2-pkcs11/1.10+swtpm` both printed `yes`, though 1536 is recorded `no` (1.10+swtpm.toml:68) and 1280 lies between a yes and that no. With the suggested fix the gate (gate.rs:205-211) would note "not decided" rather than refuse, so the gain is an honest unknown, not a refusal. [run]
`crates/profile/src/effective.rs:191-196`. "A size between two that generated is yes" uses only
the min and max of `can_bits`; a refusal in between is ignored. `tpm2-pkcs11/1.10+swtpm`:
1024 yes, 1536 no, 2048 yes, 3072 yes, reported range 1024–3072. `generate("CKK_RSA", None,
Some(2560))` (or 1280) answers yes, though a TPM generates only its discrete sizes; the AMD
fTPM profile (1024 yes, 1536 no, 2048 yes) answers 1792 yes likewise. Reachable from
`gate.rs:205` with `modulusBits = 2560` on a tpm2 token: `validate` passes and the failure comes
from `C_GenerateKeyPair` instead of a refusal with evidence. Fix: yes only when the nearest
tried size below and the nearest above both generated; otherwise unknown.
[read]

### F3. `add` is ignored for a profile without an advertisement — nit

`crates/profile/src/effective.rs:117-126`. The empty-`advertise` check returns Unknown before
`m.add` is consulted, so a partial profile that explicitly records a mechanism as usable
(`add = ["CKM_X"]`) still answers unknown for it. The `partial` flag itself is never read
here; "partial" is inferred from `advertise.is_empty()`. Check `add` before the emptiness test.
[read]

### F4. `curve` does not let a layer decide without a module — nit

`crates/profile/src/effective.rs:229-231`. `mechanism` and `generate` let a layer's
subtraction or `cannot` row answer *no* with no module profile selected; `curve` returns
"no module profile selected" first, so a hardware layer's refused curve is unknown in a
layer-only query. Minor inconsistency.
[read]

## Design

- The interpolation and fall-through rules (F1, F2) are the only places where the algebra
  infers *yes* from absence; everything else is "a row said so". A small table-driven test over
  every committed module profile ("no verdict is yes unless a row or reported range implies it")
  would pin D5.

## Checked, no issue

- Layer order: subtraction, layer `cannot` rows (item only), then restrictions, before the
  module; `Restrict` with `Operation::Other` restricts nothing, as its doc says.
- Size bounds are inclusive at both ends (layer restriction and module `reported`).
- `parameter_set_key_type` maps only ML-DSA/ML-KEM/SLH-DSA, PBKDF2 PRFs to none.
- `oaep()` distinguishes never-probed (`None`) from probed-none (`Some([])`).
- "Withdrawn" ISSUES.md item: no/unknown exit 15/16 doc is correct.
