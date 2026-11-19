# Review: scripts/local-tests.sh (130 lines)

Reviewed 2026-11-18 [read]. Summary: runs the token suites outside Nix as the crane check phase
does: the patched cryptoki (patches applied to a registry copy, wired in through a tree copy's
`.cargo/config.toml`), the Nix build's features, token templates, per-test environments through
nix/test-tokens.sh, and every `*_REQUIRE` set. It refuses to run unless cryptoki resolves to the
patched copy. A good tool; the weak spot is how it learns the patch and feature lists.

## Findings

### F1. The patch and feature lists are scraped from Nix source with sed — practice

`scripts/local-tests.sh:50-60`. `features` is every quoted line between `^  features = \[$` and
the first `^  \]$`; `patches` every `./…patch` line inside the `cryptoki = {` block. Both depend
on nixfmt's exact layout and on nothing else in those ranges being a quoted string. A
reformatting, a comment containing a quoted word, or a feature list built with `++` inside the
first bracket changes the result silently; the guards only catch an empty result. `nix eval
--json --file nix/package-common.nix` (with stub arguments) or a `passthru.cargoFeatures` on the
package would give the same lists exactly. [read]

**Fixed (2026-11-18):** version, patches and features from `nix eval --json .#cakeys.patchedCryptoki` (nix/package.nix passthru). Test: local-tests run with tpm2 and p11kit filters passes.

### F2. `exec` into `CAKEYS_LOCAL_TESTS_THEN` drops the cleanup trap — nit

`scripts/local-tests.sh:101`, `:127-129`. The EXIT trap that removes `$T` does not survive
`exec`, so every `nix run .#coverage-full` leaves the temporary directory (token templates, the
kryoptic database, and coverage-full's ftpm store under it) in `/tmp`. Run the script as a child
(`bash "$CAKEYS_LOCAL_TESTS_THEN" ...; exit $?`) instead of `exec`. [read]

**Fixed (2026-11-18):** the THEN script runs as a child, then `exit`.

### F3. The test runner variable is x86_64-only — nit

`scripts/local-tests.sh:125`. `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER`: on aarch64-linux
the runner is not used, so every test shares one token set while the `*_REQUIRE` variables demand
the TPM and p11-kit environments that only the runner starts. Compute the variable from
`rustc -vV`'s host triple. [read]

**Fixed (2026-11-18):** runner variable from `rustc -vV`'s host triple.

## Design

- The script is a hand copy of nix/package-common.nix's preCheck (it says so); see
  REVIEW_nix_package-common.nix.md F2. One sourced token-env script would remove the copy.

## Checked, no issue

- Patched copy keyed by version and patch contents; rebuilt when a patch changes.
- `cargo metadata --locked` against the repository's lock, and the resolved cryptoki checked to be
  the patched path, so a stale patch setup cannot pass unnoticed.
- `CAKEYS_TPM_PORT_BASE` randomised per run below the ephemeral range.
