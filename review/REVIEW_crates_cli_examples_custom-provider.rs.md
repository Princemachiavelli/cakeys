# Review: crates/cli/examples/custom-provider.rs (22 lines)

Reviewed 2026-11-18 [read]. Summary: the downstream-binary example: a code provider with only
`name` and `matches`, linked through `default_registry().with(Acme)`. Compiles against the
current trait (every other hook has a default).

## Findings

### F1. The usage line uses the old address grammar — nit

`crates/cli/examples/custom-provider.rs:2`.
`… verify <spec> --token acme` predates the object-first address (V4): every verb now takes
`<object> [--spec S] [--token T]` (CAKEYS.md), so a positional spec name is refused (17) unless
it happens to be an object's name too. Write `verify <object> --token acme`. [read]

**Fixed (2026-11-18):** the usage line reads `verify <object> --token acme`.

## Design

- A provider with no hooks beyond `matches` is what a module profile's `[match] manufacturer`
  already gives without code (`provider::Data`, ARCHITECTURE.md "Data providers"); the example
  would teach more if it showed one real hook (`repair` or `check_options`), or said that a
  matching profile is the first thing to try.

## Checked, no issue

- `matches` compares `ModuleInfo::manufacturer` exactly; that field is what token resolution
  matches on as well.
