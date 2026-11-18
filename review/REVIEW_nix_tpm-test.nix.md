# Review: nix/tpm-test.nix (127 lines)

Reviewed 2026-11-18 [read]. Summary: VM test of `sandbox.tpm2`: the udev ACL lists every build
GID (128 slots with auto UIDs, nixbld otherwise), a build requiring the token feature uses the
TPM, a plain build does not see the device, removing the ACL removes access, and a change event
restores it. A good negative control.

## Findings

### F1. Slot arithmetic hard-coded — nit

`nix/tpm-test.nix:88-89`, `:102`. `872415232`, `65536` and `128` repeat nix/module.nix's
defaults (lines 24-25, 31). If the module's defaults or the node's `nix.settings` change, the test
fails for the wrong reason; interpolate them from the node's config. [read]

## Design

None.

## Checked, no issue

- `udevadm settle` after `/dev/tpmrm0` appears, before reading the ACL.
- The uid_map/gid_map assertion ties the ACL entry to the slot's first UID.
