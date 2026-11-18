# Review: nix/examples.nix (76 lines)

Reviewed 2026-11-18 [read]. Summary: `checks.examples`: runs each example's run.sh on throwaway
tokens (SoftHSM, kryoptic, swtpm), validates the YubiKey keys.toml, and evaluates the TLS
example's two units and the secure-boot derivation. A good drift guard for the examples.

## Findings

### F1. The EFI stub path is x86_64-only, so `checks.aarch64-linux.examples` fails — bug

**Verification:** confirmed. checks.nix:297-312 defines `examples` for every Linux system (flake.nix:51-55 lists aarch64-linux), nix/examples.nix:56 hardcodes `linuxx64.efi.stub`, examples/secure-boot/run.sh:43 signs `$EFI_STUB`, and the pinned nixpkgs gives `efiArch = "aa64"` on aarch64 (lib/systems/default.nix:390-398). One correction: the `uki` runCommand (:29) is only instantiated via `signDrv = …drvPath`, never built, so only the run.sh step fails. [read]
`nix/examples.nix:29`, `:56`. Both the `uki` stand-in (`cp
${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub $out`) and `EFI_STUB` name the x64 stub.
The check is defined for every Linux system (checks.nix:297-312, `isLinux`), and systemd names the
stub by `efiArch` (`aa64` on aarch64, per lib/systems in the pinned nixpkgs), so on aarch64-linux
the evaluation's `uki` build and secure-boot/run.sh's signing step both fail on a missing file.
Not seen because CI builds x86_64 only (REVIEW_flake.nix.md F1). Use
`linux${pkgs.stdenv.hostPlatform.efiArch}.efi.stub` in both places. [read]

### F2. The evaluated examples are not the files as written — nit

`nix/examples.nix:21`, `:24-31`. The TLS units are evaluated with `lock` forced to a string, and
sign.nix with its `./keys.lock`, which does not exist in examples/secure-boot, so nix/lib.nix
drops `--lock` silently (lib.nix:65). The comment says so for TLS; for sign.nix the evaluated
`check` is a lockless one, which a reader of the check would not expect. [read]

### F3. Redundant `set -o pipefail` — nit

`nix/examples.nix:67`. stdenv already sets it; harmless. [read]

## Design

- `signDrv = builtins.unsafeDiscardStringContext signed.drvPath` forces evaluation of the
  secure-boot derivation without building it (it needs a real TPM); a sound trick.

## Checked, no issue

- Each run.sh failure propagates: the loop runs in a pipeline subshell with `errexit` inherited,
  and `pipefail` carries the status through `tee`.
- `CAKEYS_ALLOW_NIX_STORE_KEYS=1` is scoped to this derivation.
