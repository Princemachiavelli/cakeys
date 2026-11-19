# What the NixOS VM tests share (nix/test.nix, nix/module-test.nix, nix/tpm-test.nix): the
# guest's SoftHSM token, the keys.toml naming it, and the one way to build inside the guest, so
# the three tests cannot drift apart. Plain data: `import ./vm-common.nix`.
let
  stateDir = "/var/lib/softhsm";
in
{
  inherit stateDir;

  # The guest's SoftHSM token store, configuration and PIN file, all under stateDir.
  softhsm = {
    # NixOS configuration: the one token setup (nix/token-env.sh, review D9) in the guest, and
    # every shell's SOFTHSM2_CONF.
    config = {
      environment.etc."km/token-env.sh".source = ./token-env.sh;
      environment.variables.SOFTHSM2_CONF = "${stateDir}/softhsm2.conf";
    };
    # testScript: the arguments of a `machine.succeed(...)` that write the configuration and
    # make token `kmtest` (user PIN 1234, SO PIN 5678) as token-env.sh does everywhere else,
    # and the PIN file keys.toml names.
    init = ''
      ". /etc/km/token-env.sh && softhsm_conf ${stateDir} && softhsm_init kmtest",
      "echo 1234 > ${stateDir}/pin",
    '';
    # Where softhsm_conf keeps the tokens: for a tmpfiles rule.
    tokens = "${stateDir}/softhsm-tokens";
  };

  # keys.toml's token and its signing key, on SoftHSM module `module`; a test appends its own
  # specs (`signing-soft` names the key there) and further objects.
  keysToml =
    module:
    ''
      [tokens.softhsm]
      module = "${module}"
      tokenLabel = "kmtest"
      pinFile = "${stateDir}/pin"

      [objects.signing]
      class = "CKO_PRIVATE_KEY"
      keyType = "CKK_EC"
      curve = "secp256r1"
    '';

  # testScript: `guest_build(m, attr, nonce)` builds attribute `attr` of /etc/km/builds.nix in
  # guest `m` (a fresh `nonce` makes a new derivation) and returns what the build wrote.
  guestBuild = ''
    def guest_build(m, attr, nonce):
        out = m.succeed(
            f"nix-build /etc/km/builds.nix -A {attr} --argstr nonce {nonce} --no-out-link 2>&1"
        ).strip().splitlines()[-1]
        return m.succeed(f"cat {out}")
  '';
}
