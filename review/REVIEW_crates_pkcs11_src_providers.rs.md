# Review: crates/pkcs11/src/providers.rs (49 lines)

Reviewed 2026-11-18 [read]. Summary: the built-in p11-kit provider (detection by manufacturer, a
hint) and notes on the data providers. Trivial and correct; one stale sentence.

## Findings

### F1. The module doc's list of provider crates omits aws-cloudhsm — nit

`crates/pkcs11/src/providers.rs:2-3`. "Modules with real fix-ups or native paths (ykcs11,
tpm2-pkcs11, kmsp11) are provider crates": aws-cloudhsm is one too (`crates/aws-cloudhsm`,
`repair` and `stand_in`). Same drift as `REVIEW_crates_pkcs11_src_provider.rs.md` F1. [read]

## Design

None.

## Checked, no issue

- `P11Kit::matches` compares the trimmed `C_GetInfo` manufacturer exactly ("PKCS#11 Kit"),
  which `resolution`'s forwarder detection and the `p11-kit` layer use as well.
