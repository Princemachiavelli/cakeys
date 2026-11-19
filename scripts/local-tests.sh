#!/usr/bin/env bash
# Run the test suites outside Nix the way the crane check phase does (nix/package-common.nix
# preCheck, nix/test-tokens.sh under cargo-nextest): a token set per test, every reference token
# required, and the patched cryptoki the Nix build compiles. Seconds per test instead of a build.
#
#   scripts/local-tests.sh [cargo-nextest run arguments...]
#   scripts/local-tests.sh -E 'test(host_moves)'
#
# The patches (nix/patches/cryptoki-*.patch, and upstream/rust-cryptoki/ drafts applied as they
# are) and the features that use them, both as
# nix/package-common.nix lists them: the patches are applied to the registry's cryptoki under
# target/local-tests/, never vendored in the tree, and the features enabled. The run happens in
# a copy of the working tree, target/local-tests/tree, whose .cargo/config.toml patches
# cryptoki to that copy, so the repository's Cargo.lock is never touched. It refuses to run
# unless the build resolves cryptoki to the patched copy, and the reference suites run with
# their *_REQUIRE variables set, so a test needing the patch fails instead of skipping.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
[ -n "${IN_NIX_SHELL:-}" ] || exec nix develop "$repo" -c "$0" "$@"
cd "$repo"
work=$repo/target/local-tests
mkdir -p "$work"

# The modules and tools the check phase uses: the flake's own packages and nixpkgs.
mapfile -t paths < <(nix build --no-link --print-out-paths --inputs-from . .#softhsm-unwrap-value-len .#tpm2-pkcs11-vendor.out \
  nixpkgs#kryoptic nixpkgs#p11-kit.out nixpkgs#tpm2-pkcs11.out nixpkgs#cargo-nextest nixpkgs#rsync nixpkgs#gnupatch nixpkgs#jq \
  nixpkgs#openssl.bin nixpkgs#pkcs11-provider)
path_of() {
  local p
  for p in "${paths[@]}"; do
    case ${p#/nix/store/*-} in "$1"*) echo "$p" && return ;; esac
  done
  echo "local-tests: no $1 among ${paths[*]}" >&2
  exit 1
}
softhsm=$(path_of softhsm-unwrap-value-len)
kryoptic=$(path_of kryoptic)
p11kit=$(path_of p11-kit)
tpm2=$(path_of tpm2-pkcs11-1)
tpm2_vendor=$(path_of tpm2-pkcs11-vendor)
nextest=$(path_of cargo-nextest)
rsync=$(path_of rsync)
gnupatch=$(path_of patch)
jq=$(path_of jq)
openssl=$(path_of openssl)
provider=$(path_of pkcs11-provider)
export PATH=$softhsm/bin:$nextest/bin:$rsync/bin:$gnupatch/bin:$jq/bin:$openssl/bin:$PATH

# The cryptoki the Nix build patches: its version and patch list, read from package-common.nix.
block=$(sed -n '/^  cryptoki = {$/,/^  };$/p' nix/package-common.nix)
version=$(sed -n 's/^ *version = "\(.*\)";$/\1/p' <<<"$block")
# Paths relative to nix/: ./patches/ (local fixes) and ../upstream/ (drafts applied as they are).
mapfile -t patches < <(sed -n 's|^ *\(\.\{1,2\}/.*\.patch\)$|nix/\1|p' <<<"$block")
[ -n "$version" ] && [ "${#patches[@]}" -gt 0 ] || {
  echo "local-tests: no cryptoki version or patches in nix/package-common.nix" >&2
  exit 1
}
# The features the Nix build enables with the patches (package-common.nix `features`, before
# its `++` additions for a build without tpm2): what only the patched cryptoki compiles.
features=$(sed -n '/^  features = \[$/,/^  \]$/s/^ *"\(.*\)"$/\1/p' nix/package-common.nix | paste -sd, -)
[ -n "$features" ] || {
  echo "local-tests: no features in nix/package-common.nix" >&2
  exit 1
}
locked=$(cargo metadata --format-version 1 --locked |
  jq -r '.packages[] | select(.name == "cryptoki" and .source != null) | "\(.version) \(.manifest_path)"')
[ "${locked%% *}" = "$version" ] || {
  echo "local-tests: Cargo.lock has cryptoki ${locked%% *}, nix/package-common.nix patches $version" >&2
  exit 1
}
source_dir=$(dirname "${locked#* }")
# Keyed by the version and the patches' contents: a changed patch is applied afresh.
stamp=$( (echo "$version" && cat "${patches[@]}") | sha256sum | cut -c1-16)
patched=$work/cryptoki-$version-$stamp
if [ ! -f "$patched/.patched" ]; then
  rsync -a --delete --chmod=u+w "$source_dir/" "$patched/"
  for p in "${patches[@]}"; do
    patch --batch --forward --silent -d "$patched" -p1 <"$p" || {
      echo "local-tests: $p does not apply to cryptoki $version" >&2
      exit 1
    }
  done
  touch "$patched/.patched"
fi

tree=$work/tree
# Not the tree: build output, git's own, and other sessions' worktrees (.claude), which change underfoot.
rsync -a --delete --exclude /target --exclude /.git --exclude '/result*' --exclude /.cargo --exclude /.claude "$repo/" "$tree/"
mkdir -p "$tree/.cargo"
printf '[patch.crates-io]\ncryptoki = { path = "%s" }\n' "$patched" >"$tree/.cargo/config.toml"
cd "$tree"
export CARGO_TARGET_DIR=$work/target
resolved=$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "cryptoki") | .manifest_path')
[ "$resolved" = "$patched/Cargo.toml" ] || {
  echo "local-tests: cryptoki resolves to $resolved, not the patched $patched" >&2
  exit 1
}

# The token templates, as preCheck makes them.
T=$(mktemp -d "${TMPDIR:-/tmp}/local-tests.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
export TMPDIR=$T HOME=$T
export SOFTHSM2_CONF=$T/softhsm2.conf
mkdir -p "$T/softhsm-tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$T/softhsm-tokens" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678 >/dev/null
export CAKEYS_TEST_MODULE=$softhsm/lib/softhsm/libsofthsm2.so CAKEYS_TEST_REQUIRE=1
export KRYOPTIC_CONF=$T/kryoptic.conf
printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' "$T/kryoptic.sql" >"$KRYOPTIC_CONF"
export CAKEYS_KRYOPTIC_MODULE=$kryoptic/lib/libkryoptic_pkcs11.so CAKEYS_KRYOPTIC_REQUIRE=1
pkcs11-tool --module "$CAKEYS_KRYOPTIC_MODULE" --init-token --slot 1 --so-pin 5678 --label kmtest >/dev/null
pkcs11-tool --module "$CAKEYS_KRYOPTIC_MODULE" --token-label kmtest --login --login-type so \
  --so-pin 5678 --init-pin --pin 1234 >/dev/null
export CAKEYS_TOKEN_TEMPLATE=$T/token-template
mkdir -p "$CAKEYS_TOKEN_TEMPLATE"
cp -r "$T/softhsm-tokens" "$T/kryoptic.sql" "$CAKEYS_TOKEN_TEMPLATE/"
export CAKEYS_P11KIT_ENV_SH=$tree/nix/p11kit-test-env.sh CAKEYS_TPM_ENV_SH=$tree/nix/tpm2-test-env.sh
export CAKEYS_P11KIT_CLIENT=$p11kit/lib/pkcs11/p11-kit-client.so CAKEYS_P11KIT_REQUIRE=1
export CAKEYS_TPM_MODULE=$tpm2/lib/libtpm2_pkcs11.so CAKEYS_TPM_REQUIRE=1
export CAKEYS_TPM_VENDOR_MODULE=$tpm2_vendor/lib/libtpm2_pkcs11.so CAKEYS_TPM_VENDOR_REQUIRE=1
# A swtpm port range of this run's own, above the check phase's 24000 and below the kernel's
# ephemeral ports (32768 on), which a client's own connections take: two local runs at once (two
# worktrees) would otherwise take the same ports (nix/test-tokens.sh).
export CAKEYS_TPM_PORT_BASE=${CAKEYS_TPM_PORT_BASE:-$((24256 + RANDOM % 60 * 128))}
export CAKEYS_PKCS11_PROVIDER_DIR=$provider/lib/ossl-modules
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="bash $tree/nix/test-tokens.sh"
# A script named here takes the place of the test run, in this environment (scripts/coverage-full.sh).
if [ -n "${CAKEYS_LOCAL_TESTS_THEN:-}" ]; then
  exec bash "$CAKEYS_LOCAL_TESTS_THEN" "$features" "$@"
fi
cargo nextest run --workspace --features "$features" --no-fail-fast "$@"
