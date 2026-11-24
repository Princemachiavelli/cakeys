#!/usr/bin/env bash
# Run the test suites outside Nix the way the crane check phase does (nix/package-common.nix
# preCheck, nix/test-tokens.sh under cargo-nextest): a token set per test, every reference token
# required, and the patched cryptoki the Nix build compiles. Seconds per test instead of a build.
#
#   scripts/local-tests.sh [cargo-nextest run arguments...]
#   scripts/local-tests.sh -E 'test(host_moves)'
#
# The patches (nix/patches/cryptoki-*.patch, and upstream/rust-cryptoki/ drafts applied as they
# are) and the features that use them, both as the Nix build has them (nix/package-common.nix,
# evaluated through `.#cakeys.patchedCryptoki`): the patches are applied to a copy of cargo's
# checkout of the rust-cryptoki repository (the git source Cargo.toml names) under
# target/local-tests/, never vendored in the tree, and the features enabled. The run happens in
# a copy of the working tree, target/local-tests/tree, whose .cargo/config.toml patches
# cryptoki and cryptoki-sys to that copy, so the repository's Cargo.lock is never touched. It
# refuses to run unless the build resolves cryptoki to the patched copy, and the reference suites
# run with their *_REQUIRE variables set, so a test needing the patch fails instead of skipping.
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

# The cryptoki the Nix build patches (its version and patches, as store paths) and the features
# it enables with them, as the build itself has them (nix/package-crane.nix `patchedCryptoki`,
# from nix/package-common.nix): evaluated, not read from the Nix source.
build=$(nix eval --json .#cakeys.patchedCryptoki)
version=$(jq -r .version <<<"$build")
mapfile -t patches < <(jq -r '.patches[]' <<<"$build")
features=$(jq -r '.features | join(",")' <<<"$build")
[ -n "$version" ] && [ "${#patches[@]}" -gt 0 ] && [ -n "$features" ] || {
  echo "local-tests: .#cakeys.patchedCryptoki has no cryptoki version, patches or features: $build" >&2
  exit 1
}
locked=$(cargo metadata --format-version 1 --locked |
  jq -r '.packages[] | select(.name == "cryptoki" and .source != null) | "\(.version) \(.manifest_path)"')
[ "${locked%% *}" = "$version" ] || {
  echo "local-tests: Cargo.lock has cryptoki ${locked%% *}, nix/package-common.nix patches $version" >&2
  exit 1
}
# cryptoki is a git source (Cargo.toml): cargo's checkout of the whole rust-cryptoki repository,
# of which the crate is the cryptoki/ subdirectory (cryptoki-sys next to it).
crate_dir=$(dirname "${locked#* }")
checkout=$(dirname "$crate_dir")
# Keyed by the checkout, the version and the patches' contents: a changed patch is applied afresh.
stamp=$( (echo "$checkout $version" && cat "${patches[@]}") | sha256sum | cut -c1-16)
patched=$work/cryptoki-$version-$stamp
if [ ! -f "$patched/.patched" ]; then
  rsync -a --delete --chmod=u+w --exclude /.git "$checkout/" "$patched/"
  for p in "${patches[@]}"; do
    patch --batch --forward --silent -d "$patched/cryptoki" -p1 <"$p" || {
      echo "local-tests: $p does not apply to cryptoki $version" >&2
      exit 1
    }
  done
  touch "$patched/.patched"
fi
# The URL the workspace names the source by, to patch it (Cargo.toml).
git_url=$(sed -n 's|^cryptoki = { git = "\([^"]*\)".*|\1|p' Cargo.toml)
[ -n "$git_url" ] || {
  echo "local-tests: no git source for cryptoki in Cargo.toml" >&2
  exit 1
}

tree=$work/tree
# Not the tree: build output, git's own, and other sessions' worktrees (.claude), which change underfoot.
rsync -a --delete --exclude /target --exclude /.git --exclude '/result*' --exclude /.cargo --exclude /.claude "$repo/" "$tree/"
mkdir -p "$tree/.cargo"
printf '[patch."%s"]\ncryptoki = { path = "%s/cryptoki" }\ncryptoki-sys = { path = "%s/cryptoki-sys" }\n' \
  "$git_url" "$patched" "$patched" >"$tree/.cargo/config.toml"
cd "$tree"
export CARGO_TARGET_DIR=$work/target
resolved=$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "cryptoki") | .manifest_path')
[ "$resolved" = "$patched/cryptoki/Cargo.toml" ] || {
  echo "local-tests: cryptoki resolves to $resolved, not the patched $patched/cryptoki" >&2
  exit 1
}

# The token templates, as preCheck makes them (nix/token-env.sh).
T=$(mktemp -d "${TMPDIR:-/tmp}/local-tests.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
export TMPDIR=$T HOME=$T
export CAKEYS_TOKEN_ENV_SH=$tree/nix/token-env.sh
# shellcheck source=nix/token-env.sh
. "$CAKEYS_TOKEN_ENV_SH"
softhsm_conf "$T"
softhsm_init kmtest
export CAKEYS_TEST_MODULE=$softhsm/lib/softhsm/libsofthsm2.so CAKEYS_TEST_REQUIRE=1
kryoptic_conf "$T"
export CAKEYS_KRYOPTIC_MODULE=$kryoptic/lib/libkryoptic_pkcs11.so CAKEYS_KRYOPTIC_REQUIRE=1
kryoptic_init "$CAKEYS_KRYOPTIC_MODULE" kmtest
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
# cargo's target runner for the host's triple (CARGO_TARGET_<TRIPLE>_RUNNER), as the Nix build
# names it: on any other triple's variable cargo would not use it, and every test would share
# one token set while the *_REQUIRE variables demand what only the runner starts.
host=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host" ] || {
  echo "local-tests: rustc -vV names no host triple" >&2
  exit 1
}
host=${host^^}
export "CARGO_TARGET_${host//-/_}_RUNNER=bash $tree/nix/test-tokens.sh"
# A script named here takes the place of the test run, in this environment
# (scripts/coverage-full.sh). A child, not exec: this script's EXIT trap removes $T afterwards.
if [ -n "${CAKEYS_LOCAL_TESTS_THEN:-}" ]; then
  bash "$CAKEYS_LOCAL_TESTS_THEN" "$features" "$@"
  exit
fi
cargo nextest run --workspace --features "$features" --no-fail-fast "$@"
