# Review: nix/package.nix (46 lines)

Reviewed 2026-11-18 [read]. Summary: the regular `buildRustPackage` build (`packages.cakeys`,
the NixOS module's default package): common args, the cryptoki patches applied to the vendored
copy in `postPatch`, nextest with nix/test-tokens.sh as runner, the shared features. Small and
correct.

## Findings

None.

## Design

- This is the build deployments get (flake.nix:99), but no check builds it; it is "built on
  demand" (checks.nix:16-18). Its only divergence from the crane build is the patch mechanism
  (lines 22-32 here vs. `overrideVendorCargoPackage`) and the absent traced coverage pass, both
  small, but a break in this `postPatch` would only be seen by a user.

## Checked, no issue

- The patch loop refuses unless exactly one `cryptoki-<version>` directory was patched
  (line 31), so a cryptoki bump cannot silently skip the patches.
- `buildFeatures`/`buildNoDefaultFeatures` carry over to the check phase (`checkFeatures`
  defaults to them), so the tests run with `rv-value`, `sign-after-init` and `kwp`.
