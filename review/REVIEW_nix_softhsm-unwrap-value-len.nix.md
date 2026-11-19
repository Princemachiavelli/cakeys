# Review: nix/softhsm-unwrap-value-len.nix (27 lines)

Reviewed 2026-11-18 [read]. Summary: SoftHSM 2.7 with the four upstream/softhsm patches (#628
CKA_VALUE_LEN on unwrap, #857 multi-part ECDSA, #897 no static teardown, #834 private OpenSSL
context), optionally with SoftHSM's own test suite. The SoftHSM every token suite runs on.

## Findings

### F1. The name says one patch; the package carries four — nit

`nix/softhsm-unwrap-value-len.nix:15`. `pname = "softhsm-unwrap-value-len"`, and the attribute,
the check and scripts/local-tests.sh use that name, while the build now also changes OpenSSL
context handling, ECDSA streaming and teardown. A reader choosing a SoftHSM for profile
regeneration (scripts/regen-profiles.sh, which takes stock SoftHSM) has no hint that this is
"SoftHSM as the tests see it". Something like `softhsm-patched` would say it. [read]

**Fixed (2026-11-18):** header says it is SoftHSM as the tests see it, all four patches; name kept (31 references).

## Design

- Deployments run stock 2.7.0 while every suite and the profile conformance test run this build;
  docs/CAPROBE_MIGRATION.md:224-227 keeps the profile rows independent of #628, but #857 changes
  what multi-part ECDSA does. See REVIEW_scripts_regen-profiles.sh.md F1.

## Checked, no issue

- `withTests` adds cppunit as a build input (configure needs it) and turns on `doCheck`.
