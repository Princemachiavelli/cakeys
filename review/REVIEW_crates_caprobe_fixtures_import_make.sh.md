# Review: crates/caprobe/fixtures/import/make.sh (37 lines)

Reviewed 2026-11-18 [read]. Summary: generates the fixed test keys caprobe's import probes send
(PKCS#8 EC per curve, Ed25519, RSA 1024-8192, AES values, a self-signed certificate), recording
the OpenSSL version. Run once; the outputs are committed. Fine.

## Findings

### F1. "Run once, from anywhere", but the output path is relative to the caller — nit

`crates/caprobe/fixtures/import/make.sh:3-4`. The example invocation passes a repository-relative
path, so it only writes the fixtures in place when run from the repository root. Also worth saying
that a rerun replaces every key (all random), which changes what the profiles' import rows were
measured with. [read]

## Design

None.

## Checked, no issue

- EC keys are converted to PKCS#8 explicitly (`genpkey -outform DER` would give SEC1), with named
  curves.
