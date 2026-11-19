# Review: .config/nextest.toml (6 lines)

Reviewed 2026-11-18 [read]. Summary: one setting: a test still running after 10 x 60 s is killed
with its process group and fails, so a deadlocked module cannot hold a run open.

## Findings

None.

## Design

- The same 10-minute ceiling applies to the traced coverage pass and the instrumented coverage
  build (nix/package-crane.nix), which run slower than the plain pass; no test is near it today
  as far as can be read.

- The process-group kill does not reach the per-test daemons that detach (`swtpm --daemon`,
  `dbus-daemon --fork`); they are stopped by nix/test-tokens.sh's EXIT trap, which runs on the
  SIGTERM but not on a SIGKILL after the grace period. In the sandbox the build's end reaps them;
  under scripts/local-tests.sh a killed test can leave a swtpm holding its port.

## Checked, no issue

- The setting is picked up by every nextest run (the check phase, local-tests, coverage), as the
  comment says: the file is in the build's source set (nix/package-common.nix:119).
