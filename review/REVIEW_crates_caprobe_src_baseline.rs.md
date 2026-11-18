# Review: crates/caprobe/src/baseline.rs (291 lines)

Reviewed 2026-11-18 [read], in full (the 2026-11-16 review did not read it). Summary: test-only
generator of `profiles/baselines/pkcs11-3.2.toml` from the vendored OASIS headers: a line
scanner over `#define`s for sixteen constant families plus the `CKP_` split, a tiny
or-expression evaluator, the curated classes, and a TOML writer; three tests regenerate and
compare, round-trip the emitter, and pin spellings and IDs. Correct on the vendored 3.2 headers;
the one weakness is that anything the scanner cannot evaluate is skipped silently.

## Findings

### F1. A family constant whose value the scanner cannot read is dropped silently — practice

`crates/caprobe/src/baseline.rs:51-66`, `:104`.
`value` understands `0x…UL`, decimal (`1`, `2UL`) and a parenthesised `|` of literals and
earlier names; everything else returns `None` and the `#define` is skipped (104), the same path
aliases take on purpose. A future header that writes a family constant another way — a shift
(`(1UL << 31)`), a cast, `~0UL`, an or-expression naming a constant defined later, or a `+` —
loses that row from the baseline with no failure: the pinned test compares the committed file
against the same generator's output, so both sides lack it. On the vendored 3.2 headers every
skip is a genuine alias (checked below). Fix: collect the skipped family names whose value is
not a bare earlier-defined name, and fail the generator if any is left. [read]

### F2. `CAKEYS_UPDATE_BASELINE=1` rewrites the file but the same run still fails — nit

`crates/caprobe/src/baseline.rs:216`, `:219-229`.
`COMMITTED` is `include_str!`'d at compile time; after the test writes the regenerated file
(223) it compares `generated` with the old compiled-in text, so the regenerating run fails
with "not what the vendored headers generate" and only the next build passes. Compare against
the text just written (or return after writing, as `coverage.rs:405-408` does). [read]

## Design

- The classes (`curated_classes`) are name heuristics (`contains("_HMAC")`, `"KEY_WRAP"`,
  `"HSS"`/`"XMSS"`); they include legacy entries such as `CKM_KEY_WRAP_LYNKS` and
  `CKM_KEY_WRAP_SET_OAEP` in `key-wrap`. Fine for `--class` listings, worth a comment that the
  classes are vocabulary, not "what cakeys can use".

## Checked, no issue

- Aliases are skipped: `CKA_SUB_PRIME_BITS`, the six `CKM_SHA3_*/SHAKE_*_KEY_DERIVE`,
  `CKF_EC_NAMEDCURVE`, and the two self-aliases (`CKM_DSA_PROBABILISTIC_PARAMETER_GEN`,
  `CKF_MULTI_MESSAGE`), each of which also has a literal definition that is kept.
- The four array attributes (`(CKF_ARRAY_ATTRIBUTE|0x…UL)`) evaluate to `0x4000_02xx`/`0x4000_0600`
  (pinned); `CKF_DONT_BLOCK 1` (no `UL`) parses; trailing comments are ignored (only the second
  whitespace field is read).
- `*_VENDOR_DEFINED` constants are recorded for later expressions but kept out of the tables.
- No family name is `#define`d twice with different literal values in the vendored header
  (checked with rg), so the last-wins `insert` never hides a conflict.
- The `FAMILIES`/`CONFORMANCE` split is guarded by the pinned test: a new conformance profile
  would land in `parameter-sets` and change the generated file.
