# Review: crates/pkcs11/src/lib.rs (20 lines)

Reviewed 2026-11-18 [read]. Summary: module declarations and re-exports of the provider API,
`Resolved` and `Token`. No findings.

## Findings

None.

## Design

- Every module is `pub`, so `token::SessionObject`, `token::derive_any`,
  `token::with_public_default_dropped`, `Token::raw` and the template builders are public API
  used by caprobe and camigrate. That is how §4(c) shares the verbs' code with the tools, but it
  also means the crate has no internal surface: a provider crate outside the workspace (the
  `custom-provider` example) can reach the raw session. A `#[doc(hidden)]` or a `tools` module
  for what only caprobe/camigrate need would mark which items the Provider API promises.

## Checked, no issue

- The re-exports match what `cli-common` and the provider crates import (`Provider`,
  `Registry`, `ChainTime`, `Template`, `Declared`, `Half`, `Via`, `SessionKey`, ...).
