# Review: nix/fuzz.nix (159 lines)

Reviewed 2026-11-18 [read]. Summary: cargo-fuzz in two settings: `smoke` (checks.fuzz) builds
every target and runs 100 000 inputs from a fixed seed over corpora seeded from the test
fixtures; `run` (apps.fuzz) runs one target for as long as wanted in a checkout. Deterministic
and sensibly scoped.

## Findings

### F1. The target list is kept by hand beside fuzz/Cargo.toml — complexity

`nix/fuzz.nix:29-42`. The twelve names match fuzz/Cargo.toml's `[[bin]]` entries today; a target
added there and not here is built (`cargo fuzz build`) but never run by checks.fuzz, with nothing
to say so. Read the names with `(lib.importTOML ../fuzz/Cargo.toml).bin` (no IFD: the file is in
the source tree). [read]

**Fixed (2026-11-18):** targets read from fuzz/Cargo.toml's `[[bin]]` (importTOML) and exported; evaluation refuses a file in fuzz/fuzz_targets/ no entry names. Test: an extra fuzz_targets file fails evaluation (mutation-checked).

### F2. No sanitizer, so memory errors in the C the tpm2 targets link are invisible — nit

`nix/fuzz.nix:11-14`, `:117-125`. `-s none` is argued for safe Rust, and the parsers are Rust;
ISSUES.md already notes an ASan build as the cheaper complement. Listed for completeness, not
new. [read]

**Decided (2026-11-18):** no ASan smoke. The only C reached is tss2-mu, prebuilt and uninstrumented, so `-s address` would instrument only safe Rust; nixpkgs' rustc ships no sanitizer runtime (no librustc-*_rt.asan.a). Documented in nix/fuzz.nix's header. ISSUES.md's "Unsafe code and other tools" says the same.

## Design

- The smoke corpus is regenerated from fixtures in the check phase, so a fixture change re-seeds
  the run; deterministic by `-seed=1`.

## Checked, no issue

- The `seed` shell is idempotent (`cp --update=none`, `[ -e ] ||`), so `apps.fuzz` can rerun it on
  an existing corpus.
- `run` checks it is in the repository root before writing `fuzz/corpus`.
