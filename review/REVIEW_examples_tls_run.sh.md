# Review: examples/tls/run.sh (52 lines)

Reviewed 2026-11-18 [read]. Summary: the TLS key born in a software TPM, a CSR through
pkcs11-provider, a throwaway CA, one `openssl s_server` handshake with only the key file `check`
wrote, then a swapped key failing the check (10). Good.

## Findings

### F1. Server readiness by polling its log — nit

`examples/tls/run.sh:34-41`. Waits up to 10 s for `ACCEPT` in server.log, then proceeds whether or
not it appeared; a slow start makes `s_client` fail with a connection error that reads like a
cakeys failure. Fail explicitly when the loop times out. The port is fixed (24443) like lib.sh's
TPM port. [read]

## Design

None.

## Checked, no issue

- `-naccept 1` ends the server after the handshake; `wait "$server" || true` reaps it.
