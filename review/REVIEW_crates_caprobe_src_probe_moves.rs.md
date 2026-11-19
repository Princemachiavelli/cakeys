# Review: crates/caprobe/src/probe/moves.rs (683 lines)

Reviewed 2026-11-18 [read]. Summary: the import, create, export and unwrap probes: fixed test
keys imported the way the provider imports, public objects created and read back, and each key
handed to the host (RFC 5649) and wrapped toward the RSA transport key and back, every row
checked on the host. Templates go through `Provider::adjusted` as §4(c) intends. Well
structured; the issues are error propagation that bypasses the parent's cleanup, an
undetermined/no asymmetry in `export_sealed`, and argument-heavy helpers.

## Findings

### F1. Host-side encoding errors abort the whole probe and skip cleanup — risk

**Verification:** confirmed (downgraded to nit). The `?`s at moves.rs:198, :287-288 and :621-622 do propagate past `destroy_all` (probe.rs:735-737), but they encode the probe's own generated label or the config's hex slot ID (uri.rs:123-133) and embedded fixtures (public.rs:22-44): deterministic inputs that fail on every run and in the reference tests, not module answers. The skipped cleanup is probe.rs F1's, and the next run's `clear_stale` repairs it. [read]
`crates/caprobe/src/probe/moves.rs:198`, `:205`, `:287-288`, `:621-622`; `crates/caprobe/src/probe.rs:735-737`.
`locator_attrs(&loc)?` and `public_object_attrs(&public, spki)?` are cakeys' own encodings of a
fixture, not module answers, yet a failure propagates out of `probe_moves` as the probe's
error. Through `write_probes` (`probe.rs:735`) that return skips `destroy_all`, leaving every
object the earlier probes made on the token (see probe.rs F1). The function's own doc says only
"An SO login failing" stops the probe (`:83`). Scenario: a new curve fixture whose public key
`public_object_attrs` cannot encode ends the run with a host error and stale scratch keys.
Fix: treat these like the other host-side failures in this file (`undetermined` with the
reason), and keep `Err` for `so_login` only. [read]

**Fixed (2026-11-18):** the locator and public-object encodings (`host_encoding`) that fail in
`import_private`, `public_half` and `create_public` are an undetermined line naming the row;
only an SO login failing still ends the probe. Test: `the_host_encoding_fails_as_a_value`
(the encoding as a value; the probe going on past it needs a fixture cakeys cannot encode).

### F2. A key that leaves but whose unwrap template the provider refuses is reported as an unwrap refusal — practice

`crates/caprobe/src/probe/moves.rs:502-534`.
When `template(&label)` fails (the provider's `Template::Import(.., Via::Unwrap)` refusal),
the reason goes into `unwrap_refusals` (507). If every way fails that way, the function writes
`unwrap.<kt>.<on> = no` with the provider's refusal as evidence and leaves `export.sealed`
undetermined, although nothing was ever sent to `C_UnwrapKey`; a provider's refusal is not the
module's answer (cf. `probe_secrets`, which pushes the provider's refusal to `undetermined`,
`probe.rs:1566-1569`). Separately, a way whose unwrapped key is not the test key (`same` fails,
523) also lands in `unwrap_refusals`, so "the module unwrapped the wrong key" and "the module
refused to unwrap" share one `no`. Fix: keep provider refusals out of the rows (undetermined),
and keep the wrong-key case as its own evidence prefix (it already has "not the key wrapped").
[read]

**Fixed (2026-11-18):** a way the provider will not template is `untried` (`Ways`): it gives no
`no` row, and while any way is untried with none come back wrong, neither row is written and
the run names the provider's refusal. The wrong-key case keeps its "not the key wrapped" prefix
in the unwrap row's evidence. Test: `untried_ways_decide_no_row`.

### F3. `export_sealed` / `import_private` carry a lot of loose parameters — complexity

`crates/caprobe/src/probe/moves.rs:484-494`, `:177-268`.
`export_sealed` takes eight arguments behind `#[expect(clippy::too_many_arguments)]`, two of
them `&dyn Fn` closures built differently by each caller; `import_private` is ~90 lines that
build three templates, two closures over `provider`, and the export calls. A small struct for
"one test key's rows" (`cap` names, `h`, `secret`, template builder, sameness check) would let
`import_private` and `import_secret` share the export tail instead of each re-deriving it.
[read]

**Fixed (2026-11-18):** `TestKey` carries one key's rows (kind, size or curve, handle, secret,
template builder, sameness check); `exports` is the shared tail (`export_host`, then
`export_sealed`), and `export_sealed` takes four arguments, its `#[expect]` gone. Behaviour
unchanged.

### F4. `same_aes` labels a host-check failure as `Unsupported` — nit

`crates/caprobe/src/probe/moves.rs:551-561`.
A `C_Encrypt (CKM_AES_ECB)` refusal becomes `KmError::Unsupported`, which `evidence` then
prints; the error kind is never used for an exit code here, but a module that simply lacks
`CKM_AES_ECB` makes every AES import "imported, but its check value: …" undetermined (596), with
no hint that the check mechanism, not the import, is missing. A note naming the check mechanism
once would make the undetermined lines readable. [read]

**Fixed (2026-11-18):** the check's failure is `Unavailable` with the return value, and says the
host's check needs `C_Encrypt` with `CKM_AES_ECB`, so the undetermined line names the check
mechanism, not the import. Message only; no test.

### F5. Curves without a fixture get no import row and no undetermined line — nit

`crates/caprobe/src/probe/moves.rs:34-42`, `:94-101`.
`CURVE_KEYS` has seven curves; `core::id::Curve::ALL` has eight (`edwards448` has no fixture,
presumably because the host does not read Ed448 PKCS#8). The RSA sizes the host cannot read are
named in `undetermined` (94-101); a missing curve is not, so a profile simply lacks
`import.CKK_EC_EDWARDS.edwards448` with no explanation, and a future `Curve::ALL` member would
be skipped the same way. Fix: name the curves of `Curve::ALL` without a fixture in
`undetermined`, and have `the_test_keys_are_what_their_rows_name` list them explicitly. [read]

**Fixed (2026-11-18):** `unfixtured_curves` (the `Curve::ALL` names with no fixture) are named
in the run's undetermined list, and the test pins them (`edwards448`). Test:
`the_test_keys_are_what_their_rows_name`.

## Design

- The fixture tables (`CURVE_KEYS`, `RSA_KEYS`) are a third list of curves beside `core::id`'s
  `Curve::ALL` and the baseline (F5).
- SO-login detection still matches cakeys' own message (`so_login`, `:171-173`), as ISSUES.md Q3
  records; not re-reported.

## Checked, no issue

- Every object made under a probe label is tracked (`made.track`) before any later step can
  return: the public half (297), the imported key (236), unwrapped copies (515), AES imports
  (594), public objects (642). The composed method's KEKs are `SessionObject`s (449, 467).
- Slot target: only what PIV holds is imported, as SO, and the slot ends with a freshly
  generated key (116-124), as the module doc says.
- `export_host` checks what arrived on the host against the fixture's canonical SPKI or value;
  the extracted plaintext is `Zeroizing` (from `Token::extract`).
- RSA fixtures are filtered to the requested sizes; sizes the host cannot read are named in
  `undetermined`.
