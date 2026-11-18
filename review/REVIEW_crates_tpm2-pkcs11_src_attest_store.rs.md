# Review: crates/tpm2-pkcs11/src/attest/store.rs (418 lines)

Reviewed 2026-11-18 [read]. Summary: read-only reader of tpm2-pkcs11 1.10's sqlite store: the
token's primary (serialized `ESYS_TR` in YAML), the user seal object, and every `tobjects` row
(libyaml with explicit tags, duplicate keys tolerated). Parsing of the untrusted rows is
bounds-checked throughout and fuzzed; no panics found. Minor robustness points only.

## Findings

### F1. One unreadable row refuses the whole token — nit

`crates/tpm2-pkcs11/src/attest/store.rs:142-145`. `tobjects.extend(parse_tobject(&attrs)?)`:
a single row the parser refuses (another tool's row, a future attribute format, a corrupted
entry) makes every key of the token unattestable (16), although `parse_tobject` already skips
rows without key material on purpose ("no reason to refuse the rest of the store"). Parse
lazily in `find`, or keep refused rows aside and report them only if no row matches. [read]

### F2. Malformed hex in a row is read as "attribute absent" — nit

`crates/tpm2-pkcs11/src/attest/store.rs:271`. `hex(h).ok()` turns a corrupt `CKA_ID`,
`CKA_TPM2_PRIV_BLOB` or `CKA_TPM2_OBJAUTH_ENC` into `None`, which surfaces as "no certifiable
store object … with CKA_ID" (11) or "carries no private blob" (15) — wrong cause and wrong exit
code for a damaged store. Distinguish "absent" from "present but not hex" (16). [read]

### F3. Invalid UTF-8 is replaced, not refused — nit

`crates/tpm2-pkcs11/src/attest/store.rs:85-93, 280`. `String::from_utf8_lossy` silently maps bad
bytes to U+FFFD in YAML rows, the auth salt and the object-auth string; downstream hex/YAML
parsing then fails with an unrelated message (or, for the salt, the unseal fails as "is the user
PIN right?"). Refuse non-UTF-8 with a store error instead. [read]

## Design

- The token is found by `tokens.label` with `query_row`, which silently takes the first match;
  the 1.10 schema declares `label TEXT UNIQUE` (`db.py:656`) [src], so this is safe for stores
  the module wrote.
- The reader is pinned to tpm2-pkcs11 1.10 by `check_version` (mod.rs) and by integration tests,
  as the module header says; the constants (`0x8F00_0001..3`) match `CKA_VENDOR_DEFINED |
  CKA_VENDOR_TPM2_DEFINED | n`.

## Checked, no issue

- `parse_parent`: every read via `first_chunk`/`get`; `2 + name_len` cannot overflow; resource
  type must be 1 (key) and the handle persistent; transient primaries refused with a clear note.
- `parse_tobject`: duplicate YAML keys accepted (last wins, as the module writes `CKA_TOKEN`
  twice); non-integer attribute types refused; class required.
- `find`: class, presence of a private blob, exact `CKA_ID`, and label when known; 0 → 11,
  several → 12. Matches DESIGN §3.7.
- Opened `SQLITE_OPEN_READ_ONLY` (no URI flag), so a wrong directory is an error, never a new
  store.
- `hex()`'s error never quotes the value (the unsealed wrapping key passes through it).
