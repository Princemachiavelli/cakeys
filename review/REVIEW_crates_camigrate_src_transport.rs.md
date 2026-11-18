# Review: crates/camigrate/src/transport.rs (141 lines)

Reviewed 2026-11-18 [read]. Summary: the transport file type. `new` canonicalizes the SPKI and
checks its size; `parse` checks format, version and that `rfc7093m4` hashes the SPKI; `key()`
re-checks the size. Small and correct. The trust decision (`tokens::pinned`) is rightly outside
it, but its caller does not apply that decision to the copy it uses (lib.rs F3).

## Findings

### F1. `parse` does not check the key size that `new` and `key()` do — nit

`crates/camigrate/src/transport.rs:62-82` against `:42` and `:113`. A transport file with a
1024-bit key parses and plans (`plan_moves` → `side_from_transport`, `pinned`) and is refused
only at `key()`, when the export runs. The lock-pinning check makes this unlikely in practice,
since a key `transport` made is never that small, but checking in `parse` would make a dry run
refuse it too. [read]

## Design

- `provider` and `mechanisms` are outside the identity the file is checked by. See the tokens.rs
  review's Design.

## Checked, no issue

- `deny_unknown_fields`, format and version, and the SPKI's identity are all refused as 17.
  The test covers each case.
- `spki()` canonicalizes before hashing, so an edited but equivalent encoding cannot pass with
  another identity.
