# Review: crates/tpm2-pkcs11/src/ptool.rs (173 lines)

Reviewed 2026-11-18 [read]. Summary: `tpm2_ptool import` of a plaintext key through a CLOEXEC
memfd named by `/proc/<pid>/fd/N`, with the PIN on the command line (accepted, ISSUES.md) and
redacted from the tool's stderr. Subprocess handling is sound (`--opt=value` form, so no
argument injection; stdin null; exit status checked). One real bug: the `--id` value has other
semantics in `tpm2_ptool` than cakeys gives it.

## Findings

### F1. `--id` is passed as cakeys' hex, but `tpm2_ptool` stores its text verbatim as `CKA_ID` — bug

**Verification:** confirmed. `import` is a `NewKeyCommandBase` (commandlets_keys.py:221-222 in tpm2-pkcs11-1.10.1-bin), whose `__call__` passes `args['id']` to `new_key_save`, which stores `CKA_ID = hexlify(tid.encode())` (:122-123, :178, :215-218), i.e. the text's bytes; cakeys passes the hex locator ID unchanged (ptool.rs:68-70; `Locator::id` is hex, config.rs:657-659, decoded only when cakeys builds attributes, token/uri.rs:129), and the fixture `258: "3061"` read as `b"0a"` (attest/store.rs:301) shows the same. The cleanup then finds nothing (`Ok(0) => {}`, camigrate host.rs:180-182). [read, src]
`crates/tpm2-pkcs11/src/ptool.rs:68-70`. cakeys' `Locator::id` is hex of the `CKA_ID` bytes
(`"0a"` means the one byte `0x0a`). `tpm2_ptool` 1.10.1 stores
`CKA_ID: binascii.hexlify(tid.encode())` (`share/tpm2_pkcs11/tpm2_pkcs11/commandlets_keys.py:122-123`
in the store's tpm2-pkcs11-1.10.1-bin) [src], i.e. the `--id` *text* becomes the ID bytes;
this crate's own store fixture shows it: `tests/fixtures/tobject-private.yaml` has `258: "3061"`,
which `store.rs`'s test reads as `CKA_ID` = `b"0a"`. Failure scenario: `camigrate migrate` of a key
whose target locator is `{ id = "0a" }` (or label + id) into a tpm2-pkcs11 token → the key is
imported with `CKA_ID` `30 61`; `host::import_ptool` reopens and `ops::lock_import` finds nothing
under `0a` (11); the cleanup `to.destroy(dst.object, &dst.on_token.locator)`
(`crates/camigrate/src/host.rs:181-185`) finds 0 objects and says nothing (`Ok(0) => {}`), so a
copy of the key is left on the TPM under an ID nobody declared. No test imports with an ID (all
use `--key-label` only). Fix: hex-decode the locator ID and pass it as `--id=<text>` only when it
is UTF-8 without NUL (what `tid.encode()` can round-trip); otherwise refuse (17) before running
the tool, and add an import-with-ID case to the tpm2 tests. [read, src]

## Design

- `TPM2_PKCS11_TCTI`/`TPM2TOOLS_TCTI` are set from the raw `tcti` option (`:71-73`), while the
  attestation path normalises the same string (`attest/mod.rs:182-189`). Both forms are accepted
  by the TSS loader, so this is consistent today; the two consumers of one option still parse it
  separately.
- When `tcti` is unset the child inherits the environment; the store, however, is always passed
  explicitly (`--path`), so the tool cannot pick a different store than the attestation path.

## Checked, no issue

- ISSUES.md B6 "Fixed": an empty PIN is not substituted (`:84`). Verified.
- B16's note (PIN on the command line) is accepted in ISSUES.md; not re-reported.
- Arguments use `--name=value`, so a label or token label beginning with `-` cannot be read as an
  option by argparse; `Command` does no shell interpretation.
- `Command::output()` gives the child a null stdin, so the tool cannot block on a prompt.
- The memfd is `CLOEXEC` and closed (`drop(file)`) after the child exits; the PEM buffer is
  `Zeroizing` and pre-sized so it never reallocates (`pem`, `:93-106`); `contents` is dropped
  before the spawn.
- Refusals happen before the tool runs: no PIN (16), Edwards/AES/cert (15), no label or ID (17).
