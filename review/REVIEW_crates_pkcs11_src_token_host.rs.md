# Review: crates/pkcs11/src/token/host.rs (165 lines)

Reviewed 2026-11-18 [read]. Summary: the `host` path for camigrate: taking a key out by RFC 5649
wrap under a host-drawn session KEK and unwrapping it in memory (`extract`), and creating keys
from plaintext (`create_private`, `create_secret`) under a template that zeroizes itself
(`Secret`). Secret handling is careful: the KEK, the template copies and the output are all
zeroized, the session KEK is a `SessionObject`, and no plaintext reaches an error message. No
findings.

## Findings

None.

## Design

- `import_plaintext` returns before the token sees the key ("open the token again"); the
  re-open is the caller's (camigrate) responsibility, so an `ops::lock_import` on the same open
  token would report `NotFound`. That contract lives only in the doc comment; a return type
  that forces the re-open (or `Token` consumed by the call) would make it impossible to miss.

## Checked, no issue

- `extract`: the 32-byte KEK is drawn from the OS RNG into `Zeroizing`, copied only into a
  `Secret` template (wiped on drop, also on the `create_object` error path); the session KEK is
  destroyed before the blob is unwrapped; the output buffer is `Zeroizing` and truncated to the
  unwrapped length; a blob that does not unwrap is `Conflict` without content.
- `create_private`/`create_secret`: secret components are added after the provider's
  adjustment (the caller's), wrapped in `Secret` before the call; cryptoki passes attribute
  pointers without copying; the step runs as SO where the provider manages as SO.
- `Secret` has no `Debug`; `ImportCtx` (provider.rs) likewise.
- `accepts_public_keys`: probed rows first, then the migration accept rows, else yes.
