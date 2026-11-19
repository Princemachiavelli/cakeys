# Review: nix/pcsc-probe.c (14 lines)

Reviewed 2026-11-18 [read]. Summary: prints the raw return codes of `SCardEstablishContext` and
`SCardListReaders`, exiting 2 only if the context cannot be established. A diagnostic; the module
test matches on the printed codes.

## Findings

### F1. The context is never released — nit

`nix/pcsc-probe.c:8-13`. No `SCardReleaseContext` before returning; harmless in a process that
exits at once, but pcscd logs an abandoned client. [read]

**Fixed (2026-11-18):** SCardReleaseContext; builds.

## Design

- `SCardListReaders` failing still exits 0 on purpose: `SCARD_E_NO_READERS_AVAILABLE` is the
  expected answer in a VM, and the caller reads the printed code.

## Checked, no issue

- `len` is initialised and the reader buffer is NULL, so the size query cannot overrun.
