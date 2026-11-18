# Review: crates/core/tests/lock_mbt.rs (489 lines)

Reviewed 2026-11-18 [read]. Summary: the model-based test of the lock rules. quint-connect runs
`quint run --mbt` on `crates/core/spec/lock.qnt` (500 traces, 12 steps, seed `0x1`), and the
driver maps every `realise` step to a `Target` and `Resolved`, runs the real `reconcile`, checks
the lock still loads, and projects the lock back onto the model's shape for an equality check
with the model's `lock` and `verdict`. The mapping is faithful and the step/action plumbing is
strict (an unmapped action or pick fails). The weaknesses are in what the comparison can see:
the projection silently drops lock fields, the verdict is the exit code only, and nothing
checks that the 500 replayed traces reach every rule.

## Findings

### F1. The realisation projection drops fields instead of refusing them — risk

**Verification:** confirmed (downgraded to practice). `Written` (`lock_mbt.rs:213-231`) has no `deny_unknown_fields` and omits `LockRealisation`'s `observation`/`observed`/locator fields (`crates/core/src/config.rs:1134-1177`), contradicting docs/DEVELOPMENT.md:171-172 ("refuses anything the model does not name rather than dropping it"); but `lock.qnt:13-18` explicitly leaves observations, `observed` and locators out of the model, so no in-scope result is wrong today: a doc/robustness gap against future fields. [read]
`crates/core/tests/lock_mbt.rs:211-231`, `:430`. `Written` has `rename_all` but no
`deny_unknown_fields`, and it omits three of `LockRealisation`'s fields (`locator`,
`observation`, `observed`; `crates/core/src/config.rs:1134-1177`). serde ignores what it does
not name, so those are never compared, and neither would be a field added to `LockRealisation`
later. docs/DEVELOPMENT.md ("The lock model and the Rust") says the projection "refuses anything
the model does not name rather than dropping it", which is true for policy names, bindings,
`publicOnly` and provenance but not for these. Concretely, a `record` that wrote t1's locator
into t2's realisation, or stopped writing `observation`, passes. The lock-level `observations`
table (`Lock::observations`) is never looked at either. The model's header does exclude
locators and observations, so this is a documentation/robustness gap rather than a wrong result
today. Fix: add `#[serde(deny_unknown_fields)]` to `Written` and list the three as explicitly
ignored fields (`#[allow(dead_code)] locator: serde_json::Value`, etc.), so a new lock field
fails the test until the model or the projection decides about it. The `LockObject` projection
(`:411-425`) reads named fields and has the same blind spot for a new field. [read]

### F2. The verdict is the exit code only, so rules that share 14 are interchangeable — risk

**Verification:** confirmed (downgraded to practice). `Verdict::Exit(i64)` (`lock_mbt.rs:111-114`, `:390`) carries only the code and `rule` is a ghost the test never compares (`lock.qnt:250-252`), so the order among the 14-rules in `compare` (`lock.qnt:179-185`) is untested; but this is documented ("the verdict (the exit code, or whether the lock changed)", docs/DEVELOPMENT.md:101), and the review's own example (no_downgrade skipped in compare) would still differ on single-rule traces, where `object` does not fire and the verdict becomes `Ok(false)`. Only the message is at stake when two 14-rules apply at once. [read]
`crates/core/tests/lock_mbt.rs:110-114`, `:165-170`, `:388-391`. `Verdict::Exit(i64)` carries
the code, and the model's `rule` ghost (`lock.qnt:252`) is in every trace state but never read.
Twelve of the model's rules end in 14 (`type`, `spec`, `mode`, `binding`, `anchor`,
`attestation-lost`, `schemes-lost`, `replaced`, `object`, `unlinked`, `unrealised`,
`second-name`); only `attestation-id`/`mismatch` (10) and `first-use` (18) differ. If `compare` checked them in another order, or refused
a binding downgrade for the wrong reason (say the `object` drift check fired first because
`no_downgrade` was skipped in compare mode), the exit code and the unchanged lock are the
same, and the test passes. The message is what tells a user which rule fired. Fix: map each
`KmError` to a rule name (by a stable marker in `Msg`, or a rule enum on the error if one is
added) and add `rule` to `Compared`; at minimum, document that the order among the 14s is
untested. [read]

### F3. "Every rule is reached" is checked on a larger sample than the one replayed — risk

**Verification:** confirmed (downgraded to practice). Nothing asserts rule coverage of the replayed sample (`lock_mbt.rs:486` 500 traces vs `checks.nix:95` 2000; quint-connect adds `--mbt --n-traces`, quint-connect-0.1.2 `src/trace/generator/run.rs:30-42`), but `quint run lock.qnt --seed 1 --max-samples 500 --max-steps 12 --witnesses …` reaches every one of the 18 `decidedBy*` witnesses, the rarest (`attestation-lost`) in 18 of 500 traces (3.6%), so the gap is a missing guard against future drift, not a coverage hole today. [run]
`crates/core/tests/lock_mbt.rs:486`; `checks.nix:95-100`. `checks.quint` runs 2000 traces at
`--seed 1` and fails if a `decidedBy*` witness is never seen. This test replays 500 traces at
seed `0x1`, the same seed, so at most a prefix of that sample (and not even that if quint-connect's
extra `--mbt`/`--n-traces` flags change the generator's path). A witness seen only in traces
501-2000 says nothing about the replay. docs/DEVELOPMENT.md cites the witness check as part of
"what says the test is worth something", but nothing shows the 500 traces the Rust sees contain,
for example, an `attestation-id` (10) or `second-name` run. A model change that makes a rule rarer
keeps `checks.quint` green while the replay silently stops exercising it. Fix: read `rule` in
`step` (or from the state) into a `BTreeSet` on `Mbt`, and assert after the replay that every
rule name was seen (quint-connect's runner owns the loop, so do it in a `Drop` or a second
`#[test]` that runs `quint run --witnesses` with this test's exact parameters). [read]

### F4. Fixture code duplicated with properties.rs — complexity

`crates/core/tests/lock_mbt.rs:23-61`, `:255-278`; `crates/core/tests/properties.rs:17-75`.
`facts()` and `empty_lock()` are identical in both files and the keys.toml constants overlap
(same tokens, the same `aes` object and spec, `k` on t1). A change to `Facts` or `Observation`
must be made twice. Fix: a `crates/core/tests/common/mod.rs` with `facts()`, `empty_lock()` and
the shared keys.toml pieces. [read]

### F5. Policy is projected only for two attributes, with any other a hard failure — nit

`crates/core/tests/lock_mbt.rs:131`, `:435-439`. Correct today, since `Resolved.policy` is
built from `POLICY` only; noted because a future `record` that adds derived policy attributes
(e.g. from the spec's declared attributes) would fail here with "policy beyond the model's",
which is the intended loud failure. No change needed. [read]

## Design

- The model and the Rust are tied only by this test's exit-code-level observation (F2) and a
  partial projection (F1). The value claimed in docs/DEVELOPMENT.md ("a change to the lock rules
  changes the model in the same commit, or lock_mbt.rs fails") holds for anything that moves a
  verdict's code or a projected field, not for message-level or unprojected changes.
- Witness coverage (F3) belongs to the replay, not only to `checks.quint`; with the rule read
  into the driver both F2 and F3 close together.

## Checked, no issue

- Unmapped actions fail: quint-connect's `switch!` bails on an unknown action
  (`quint-connect-macros-0.1.2/src/internal/switch.rs:73`) and on a missing named pick (`:207`);
  the model has only `init` and `realise`, both mapped. `change` is a model-only pick and is
  rightly not consumed.
- The driver is reused across traces, and `init` resets `lock` and `verdict` (`:300-303`).
- `quint` missing from `PATH` makes the test fail ("Failed to execute Quint command"), not skip;
  the trace directory is a `TempDir` and cleans itself.
- `Target::new` / `parse_lock` errors propagate (`?`), so a model config the Rust refuses fails
  the run; the lock is re-parsed after every step (`:393`).
- `Mode::rank`/`Binding::rank` (`config.rs:719-766`) agree with `modeRank`/`bindingRank` in the
  model; `PopSignPin`, `PopDecrypt`, `PopUnwrap` are outside the model and rejected by the
  projection (`:465`) rather than mapped wrongly.
- `type_name` maps k2's type to "secp256r1" via k's secp256r1 config; equal `ObjectCfg`s, so
  the first match is right.
- `commitment_label` is set only for `aes`, matching the model's `labelled`.
