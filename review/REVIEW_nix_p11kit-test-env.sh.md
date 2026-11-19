# Review: nix/p11kit-test-env.sh (36 lines)

Reviewed 2026-11-18 [read]. Summary: starts `p11-kit server` over a fresh SoftHSM token `kmp11`
on a Unix socket and writes the client's address to `<dir>/env`; `down` kills it. Small and
correct for its use.

## Findings

### F1. `down` does not wait for the server to exit — nit

`nix/p11kit-test-env.sh:30`. nix/test-tokens.sh:24 runs `rm -rf "$D"` right after `down`; the
server may still be shutting down with its socket and SoftHSM's files open. nix/tpm2-test-env.sh
waits (its lines 55-60) for exactly this reason ("Directory not empty"). Wait on the PID the same
way. [read]

**Fixed (2026-11-18):** `down` waits for the server (SIGKILL after 5 s). Test: local-tests p11kit test passes.

### F2. Readiness is the socket's existence only — nit

`nix/p11kit-test-env.sh:19-26`. If the server dies after creating the socket the loop still
succeeds; a `kill -0` check in the loop would report the log at once instead of a later
connection error. [read]

**Fixed (2026-11-18):** readiness requires the server alive as well as the socket.

## Design

None.

## Checked, no issue

- `set -euo pipefail`; the server's stdin is /dev/null and its output goes to a log, so `$(...)`
  callers do not hang.
- Socket path length is documented and the callers use short directories.
