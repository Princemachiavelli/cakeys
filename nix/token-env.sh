# shellcheck shell=bash
# The software tokens the harnesses set up, written once (review D9): SoftHSM and kryoptic in a
# directory of their own, user PIN 1234, SO PIN 5678. Sourced by the check phase
# (nix/package-common.nix), the per-test runner (nix/test-tokens.sh), scripts/local-tests.sh,
# scripts/regen-profiles.sh, scripts/pkcs11-check.sh, nix/demo.sh and examples/lib.sh, so a
# SoftHSM or kryoptic setting changes in one place, and the tokens the profiles are probed on
# are the ones the check phase re-probes. Not here: the NixOS tests' VMs (nix/test.nix,
# nix/module-test.nix), scripts/xversion.sh's older SoftHSM releases, the upstream reports'
# self-contained repros, a cloud host's setup, and p11-kit's own token (nix/p11kit-test-env.sh).

# softhsm_conf DIR: SoftHSM keeps its tokens in DIR/softhsm-tokens (SOFTHSM2_CONF, exported).
softhsm_conf() {
  mkdir -p "$1/softhsm-tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$1/softhsm-tokens" >"$1/softhsm2.conf"
  export SOFTHSM2_CONF=$1/softhsm2.conf
}

# kryoptic_conf DIR: kryoptic keeps slot 1 in DIR/kryoptic.sql (KRYOPTIC_CONF, exported). The
# slot table ends the file: the reference suite appends a mechanism deny list to it
# (crates/cli/tests/common/mod.rs).
kryoptic_conf() {
  printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' "$1/kryoptic.sql" >"$1/kryoptic.conf"
  export KRYOPTIC_CONF=$1/kryoptic.conf
}

# softhsm_init LABEL: a new SoftHSM token LABEL, where softhsm_conf put them.
softhsm_init() {
  softhsm2-util --init-token --free --label "$1" --pin 1234 --so-pin 5678 >/dev/null
}

# kryoptic_init MODULE LABEL: kryoptic's slot 1 initialised as LABEL, with its user PIN.
kryoptic_init() {
  pkcs11-tool --module "$1" --init-token --slot 1 --so-pin 5678 --label "$2" >/dev/null
  pkcs11-tool --module "$1" --token-label "$2" --login --login-type so --so-pin 5678 \
    --init-pin --pin 1234 >/dev/null
}

# test_env DIR SOFTHSM KRYOPTIC P11KIT_CLIENT P11KIT_ENV_SH TPM_ENV_SH PROVIDER_DIR [TPM TPM_VENDOR]:
# the two software tokens set up in DIR, their templates for nix/test-tokens.sh, and every
# variable the suites read, each module named by its path. The check phase and
# scripts/local-tests.sh both call it, so a new suite variable is added once (review
# 2026-11-23 C-19); the TPM modules only where the caller has them.
test_env() {
  local dir=$1
  softhsm_conf "$dir"
  softhsm_init kmtest
  export CAKEYS_TEST_MODULE=$2 CAKEYS_TEST_REQUIRE=1
  kryoptic_conf "$dir"
  export CAKEYS_KRYOPTIC_MODULE=$3 CAKEYS_KRYOPTIC_REQUIRE=1
  kryoptic_init "$CAKEYS_KRYOPTIC_MODULE" kmtest
  # The templates of a per-test token set (nix/test-tokens.sh, every test's runner): the two
  # software tokens as just initialised, before any test touches them.
  export CAKEYS_TOKEN_TEMPLATE=$dir/token-template
  mkdir -p "$CAKEYS_TOKEN_TEMPLATE"
  cp -r "$dir/softhsm-tokens" "$dir/kryoptic.sql" "$CAKEYS_TOKEN_TEMPLATE/"
  # p11-kit forwarding and the software TPM: test-tokens.sh starts a server and a swtpm per test
  # for the suites that use them, and there is no shared one to fall back on (review D9).
  export CAKEYS_P11KIT_CLIENT=$4 CAKEYS_P11KIT_REQUIRE=1
  export CAKEYS_P11KIT_ENV_SH=$5 CAKEYS_TPM_ENV_SH=$6
  # OpenSSL through pkcs11-provider reads what `check --format pkcs11-provider-pem` writes.
  export CAKEYS_PKCS11_PROVIDER_DIR=$7
  if [ -n "${8:-}" ]; then
    export CAKEYS_TPM_MODULE=$8 CAKEYS_TPM_REQUIRE=1
    export CAKEYS_TPM_VENDOR_MODULE=$9 CAKEYS_TPM_VENDOR_REQUIRE=1
  fi
}
