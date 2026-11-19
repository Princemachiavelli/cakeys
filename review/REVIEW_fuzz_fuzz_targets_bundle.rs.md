# Review: fuzz/fuzz_targets/bundle.rs (11 lines)

Reviewed 2026-11-18 [read]. Summary: an export bundle's text through `Bundle::parse`; on error
the exit code must be 17. Property: "no panic, right exit code". Seeded from the sample bundle
(`nix/fuzz.nix:55`).

## Findings

### F1. No round trip, though camigrate writes the bundles it reads — practice

`fuzz/fuzz_targets/bundle.rs:8-10`. camigrate writes bundles with `Bundle::to_toml`
(`crates/camigrate/src/bundle.rs:201`, plain `toml::to_string`) and reads them on the
destination with `Bundle::parse`, which validates format, version, non-empty keys and
uniqueness and normalises entries (`bundle.rs:114-…`). A bundle that parses but whose
serialisation does not parse back, or parses to something else, would strand an export
between hosts; this target cannot see that. `Bundle` derives `PartialEq`, so the property is
direct: for `Ok(b)`, `Bundle::parse(&b.to_toml()?) == Ok(b)`.
[read]

**Fixed (2026-11-18):** Verified fixed (2026-11-18), unmarked until now.

## Design

None.

## Checked, no issue

- Exit 17 is the documented code for a malformed bundle (docs/CAMIGRATE.md D5).
