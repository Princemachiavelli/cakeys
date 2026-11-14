#!/usr/bin/env bash
# The cakeys demo (`nix run .#demo`; checked non-interactively by `checks.demo`): two software
# tokens, SoftHSM and kryoptic, in a throwaway directory, and cakeys' main ideas in five acts.
# Every step states the exit code it expects and the demo stops on any other, so it cannot
# drift from what cakeys does.
#
# Environment (set by nix/demo.nix): SOFTHSM_MODULE, KRYOPTIC_MODULE, CAKEYS_LIB (nix/lib.nix).
# DEMO_PAUSE=0 runs straight through; --keep leaves the directory for poking around.
set -euo pipefail

: "${SOFTHSM_MODULE:?}" "${KRYOPTIC_MODULE:?}" "${CAKEYS_LIB:?}"
keep=0
[ "${1:-}" = "--keep" ] && keep=1
if [ -t 0 ] && [ -t 1 ]; then pause=${DEMO_PAUSE:-1}; else pause=${DEMO_PAUSE:-0}; fi
if [ -t 1 ]; then
  bold=$'\e[1m' dim=$'\e[2m' green=$'\e[32m' red=$'\e[31m' reset=$'\e[0m'
else
  bold='' dim='' green='' red='' reset=''
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/cakeys-demo.XXXXXX")
cleanup() {
  if [ "$keep" = 1 ]; then
    echo "${dim}kept: $work (SOFTHSM2_CONF=$SOFTHSM2_CONF KRYOPTIC_CONF=$KRYOPTIC_CONF)${reset}"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT
cd "$work"

declare -A meaning=(
  [0]="ok" [10]="hash mismatch / first use: prints got:" [11]="not found" [12]="ambiguous"
  [13]="conflict" [14]="precondition failed" [15]="unsupported" [16]="unavailable"
  [17]="invalid config"
)

act() {
  printf '\n%s━━ %s ━━%s\n' "$bold" "$1" "$reset"
  shift
  for line in "$@"; do echo "$line"; done
}

wait_key() {
  if [ "$pause" = 1 ]; then
    read -r -p "${dim}[enter]${reset} " _ || true
  fi
}

# Indent output, at most `limit` lines of it.
indent() {
  awk -v max="${limit:-14}" '
		NR <= max { print "  " $0 }
		END { if (NR > max) printf "  … (%d more lines)\n", NR - max }'
}

# Run a command, show it and its output, and require the exit code `want`. With `jqf` set, its
# stdout goes through `jq -c "$jqf"` (the exit code stays the command's).
expect() {
  local want=$1 code=0 out
  shift
  if [ -n "${jqf:-}" ]; then
    printf '%s$ %s | jq -c '"'"'%s'"'"'%s\n' "$dim" "$*" "$jqf" "$reset"
    out=$( ("$@" | jq -c "$jqf") 2>&1) || code=$?
  else
    printf '%s$ %s%s\n' "$dim" "$*" "$reset"
    out=$("$@" 2>&1) || code=$?
  fi
  [ -n "$out" ] && indent <<<"$out"
  if [ "$code" = "$want" ]; then
    printf '  %s→ exit %s (%s)%s\n' "$green" "$code" "${meaning[$code]:-}" "$reset"
  else
    printf '  %s→ exit %s, expected %s: the demo no longer matches cakeys%s\n' "$red" "$code" "$want" "$reset"
    exit 1
  fi
  last=$out
}

# Show a command and its output (no exit code to check).
show() {
  printf '%s$ %s%s\n' "$dim" "$*" "$reset"
  "$@" | limit=${limit:-40} indent
}

# The `got:` hash a first use prints.
got() { sed -n 's/.*got: *\(sha256-[A-Za-z0-9+\/=]*\).*/\1/p' <<<"$last" | head -n1; }

# pkcs11-tool on the demo token of module `$1`, shown with the module's short name.
p11() {
  printf '%s$ pkcs11-tool --module %s %s%s\n' "$dim" "$(basename "$1")" "${*:2}" "$reset"
  pkcs11-tool --module "$1" --token-label demo --login --pin 1234 "${@:2}" >/dev/null 2>&1
}

# Show a command and run it quietly.
step() {
  printf '%s$ %s%s\n' "$dim" "$*" "$reset"
  "$@" >/dev/null 2>&1
}

# Append to keys.toml from stdin, and show what was added.
append() {
  printf '%s$ cat >>keys.toml%s\n' "$dim" "$reset"
  tee -a keys.toml | limit=40 indent
}

# ── Two tokens ──────────────────────────────────────────────────────────────────────────────

export SOFTHSM2_CONF=$work/softhsm2.conf
mkdir -p "$work/softhsm"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$work/softhsm" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678 >/dev/null

export KRYOPTIC_CONF=$work/kryoptic.conf
printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' "$work/kryoptic.sql" >"$KRYOPTIC_CONF"
pkcs11-tool --module "$KRYOPTIC_MODULE" --init-token --slot 1 --so-pin 5678 --label demo >/dev/null
pkcs11-tool --module "$KRYOPTIC_MODULE" --token-label demo --login --login-type so --so-pin 5678 \
  --init-pin --pin 1234 >/dev/null
echo 1234 >pin
export CAKEYS_CONFIG=$work/keys.toml

cat >keys.toml <<EOF
# Two tokens behind two different PKCS#11 modules. Where a module lives is per machine, so
# keys.toml names a variable this machine sets (\$NAME, read when the token is opened), not
# a path. Alternatives: leave module out and pass --module soft=<path> per run — what
# lib.mkKeys's modules.<token> does with a store path in a Nix build — or a bare file name,
# which is the dynamic loader's search (LD_LIBRARY_PATH; on NixOS nothing else). Whatever
# names it, keys.lock records the file actually loaded and its hash, as provenance only.
[tokens.soft]
module = "\$SOFTHSM_MODULE"
tokenLabel = "demo"
pinFile = "$work/pin"

[tokens.kryo]
module = "\$KRYOPTIC_MODULE"
tokenLabel = "demo"
pinFile = "$work/pin"

# What a key *is* (type, curve) ...
[objects.signing]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

# ... and how it must be held on a token: the policy every realisation is checked against.
[specs.signing]
object = "signing"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.soft = { locator = { CKA_LABEL = "signing" }, autoCreate = true }
EOF

act "cakeys demo" \
  "Content-addressed identity for PKCS#11 keys: a key is named by a hash of its material," \
  "pinned in keys.lock like a Nix fixed-output hash, and checked before every use." \
  "" \
  "Two fresh tokens: SoftHSM ($SOFTHSM_MODULE)" \
  "            and kryoptic ($KRYOPTIC_MODULE)." \
  "Working directory: $work"
show cat keys.toml
wait_key

# ── Act 1 ───────────────────────────────────────────────────────────────────────────────────

act "1. A key is a pinned input" \
  "First use creates the key and fails like a fixed-output derivation with a fake hash:" \
  "cakeys prints the identity it got and records nothing yet."
expect 10 cakeys realise signing --token soft --no-update-lock
first=$(got)
echo "Again: the same key is found under its locator, never a second one created."
expect 10 cakeys realise signing --token soft --no-update-lock
[ "$(got)" = "$first" ] || {
  echo "${red}a second run got another identity${reset}"
  exit 1
}
echo "Record it, like updating flake.lock. The private key also proves possession: it signs a"
echo "fresh challenge the host verifies against the public key the identity hashes (pop-sign)."
limit=13 expect 0 cakeys realise signing --token soft
echo "keys.lock: the identity per object; per token, how it was realised (and the policy it"
echo "observed, cut here). What it saw of the module and token is one [observations] entry,"
echo "shared by every realisation recorded with the same:"
show sed -n '1,/^\[realisations.signing.soft.policy\]/p' keys.lock
echo "Observations, never a verdict: the module file actually loaded (the variable resolved) and"
echo "its hash. Another path is a note; the same path with other content (replaced in place) warns."
show sed -n '/^\[observations\..*\.module\]/,/^cryptoki/p' keys.lock
echo "From now on every use is checked against the lock: identity, policy and binding."
expect 0 cakeys verify signing --token soft
wait_key

# ── Act 2 ───────────────────────────────────────────────────────────────────────────────────

act "2. What a Nix build sees" \
  "nix/lib.nix reads keys.toml and keys.lock in pure evaluation: the identity, the URI, the" \
  "system feature that routes the build to a machine with the token, and the pre-use check."
if command -v nix-instantiate >/dev/null && nix-instantiate --eval --expr 1 >/dev/null 2>&1; then
  bin=$(dirname "$(readlink -f "$(command -v cakeys)")")
  cat >keys.nix <<EOF
let keys = (import $CAKEYS_LIB).mkKeys {
  config = ./keys.toml;
  lock = ./keys.lock;
  cakeys = "$(dirname "$bin")";
  # The module for the build's pre-use check (passed as --module soft=…, in place of keys.toml's
  # \$SOFTHSM_MODULE, which a build sandbox does not set). In a flake:
  # modules.soft = "\${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
  modules.soft = "$SOFTHSM_MODULE";
};
in { inherit (keys.signing { }) id uri requiredSystemFeatures check; }
EOF
  show cat keys.nix
  printf '%s$ nix-instantiate --eval --strict --json keys.nix | jq .%s\n' "$dim" "$reset"
  nix-instantiate --eval --strict --json keys.nix | jq . | limit=40 indent
else
  echo "${dim}(no nix-instantiate here: skipping the evaluation)${reset}"
fi
echo "A derivation runs that check before it touches the key; it prints the URI to use."
expect 0 cakeys check signing.id.rfc7093m4
wait_key

# ── Act 3 ───────────────────────────────────────────────────────────────────────────────────

act "3. A lost key is never silently replaced" \
  "Delete the key behind cakeys' back, as a wiped or swapped token would."
p11 "$SOFTHSM_MODULE" --delete-object --type privkey --label signing
p11 "$SOFTHSM_MODULE" --delete-object --type pubkey --label signing
expect 11 cakeys verify signing --token soft
echo "autoCreate would make a key, but the lock pins material a new key can never match:"
expect 14 cakeys realise signing --token soft
echo "Plant a different key under the same label: its identity does not match the lock."
p11 "$SOFTHSM_MODULE" --keypairgen --key-type EC:prime256v1 --label signing --id 01 --usage-sign
expect 10 cakeys verify signing --token soft
wait_key

# ── Act 4 ───────────────────────────────────────────────────────────────────────────────────

act "4. Identity is the material, not the token" \
  "One P-256 key, imported into both tokens. Each module stores it its own way; the" \
  "identity is the SHA-256 of the canonical public key (RFC 7093 method 4) on both."
step openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out shared.pem
step openssl pkey -in shared.pem -outform DER -out shared.der
step openssl pkey -in shared.pem -pubout -outform DER -out shared.pub.der
for m in "$SOFTHSM_MODULE" "$KRYOPTIC_MODULE"; do
  p11 "$m" --write-object shared.der --type privkey --label shared --id 02 --usage-sign
  p11 "$m" --write-object shared.pub.der --type pubkey --label shared --id 02
done
append <<'EOF'

# Adopted, not created: the same object on two tokens.
[objects.shared]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.shared]
object = "shared"
attributes = { CKA_SIGN = true }
tokens.soft = { locator = { CKA_LABEL = "shared" } }
tokens.kryo = { locator = { CKA_LABEL = "shared" } }
EOF
printf '%s$ openssl dgst -sha256 -binary shared.pub.der | base64%s\n' "$dim" "$reset"
oracle=sha256-$(openssl dgst -sha256 -binary shared.pub.der | base64)
echo "The host computes the identity from the key file alone: ${bold}$oracle${reset}"
limit=13 expect 0 cakeys realise shared --token soft
limit=13 expect 0 cakeys realise shared --token kryo
locked=$(sed -n '/^\[objects.shared.ids\]/,/^\[/s/^rfc7093m4 = "\(.*\)"/\1/p' keys.lock)
echo "keys.lock holds one identity for the object and one realisation per token, each naming"
echo "what it saw of its module:"
show awk '/^\[objects.shared.ids\]/ { n = 2 } /^\[realisations.shared.[a-z]+\]$/ { print; r = 1 } r && /^observation = / { print; r = 0 } n-- > 0' keys.lock
[ "$locked" = "$oracle" ] || {
  echo "${red}locked $locked, host computed $oracle${reset}"
  exit 1
}
echo "${green}Same ID on SoftHSM, on kryoptic and on the host.${reset}"
wait_key

# ── Act 5 ───────────────────────────────────────────────────────────────────────────────────

act "5. Moving keys, planned from each side's capabilities" \
  "camigrate plans an export per object from what both modules can do (MIGRATE.md), then" \
  "moves the key sealed: through the host only wrapped, and recorded with where it came from."
append <<'EOF'

[objects.movable]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
createOn = "soft"

[specs.movable]
object = "movable"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }
tokens.soft = { locator = { CKA_LABEL = "movable" } }
tokens.kryo = { locator = { CKA_LABEL = "movable" } }

[objects.fixed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.fixed]
object = "fixed"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
tokens.soft = { locator = { CKA_LABEL = "fixed" } }
EOF
echo "No autoCreate here: that only lets first use create. Keys are created explicitly, every"
echo "pair the lock does not pin yet (signing and shared are pinned, so they are left alone):"
jqf='.[] | {object, token, rfc7093m4: .ids.rfc7093m4}' expect 0 cakeys create --token soft
echo "movable is born on soft (createOn), so kryo can only receive it. A sealed move needs a"
echo "transport key on the target: an RSA key there that may unwrap and never leaves it."
expect 15 camigrate export movable --token soft --target kryo --dry-run
append <<'EOF'

[objects.transport]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 3072

[specs.transport]
object = "transport"
attributes = { CKA_UNWRAP = true, CKA_DECRYPT = true, CKA_EXTRACTABLE = false }
tokens.kryo = { locator = { CKA_LABEL = "transport" }, binding = "pop-decrypt" }
EOF
jqf='.[] | {object, token}' expect 0 cakeys create --token kryo
echo "Now the plan is ready; a non-extractable key never leaves its token, whatever the target can do."
expect 0 camigrate export movable --token soft --target kryo --dry-run
expect 15 camigrate export fixed --token soft --target kryo --dry-run
echo "The move: wrapped on soft to kryo's transport key, unwrapped on kryo, checked against the lock."
expect 0 camigrate migrate movable --from soft --to kryo
echo "The lock keeps one identity for movable and records where kryo's copy came from:"
show awk '/^\[realisations.movable.kryo.provenance.origin\]/ { n = 4 } n-- > 0' keys.lock
expect 0 cakeys verify movable --token kryo

act "Done" \
  "Next: the NixOS VM test runs act 1 inside a real Nix build sandbox, with a consumer" \
  "derivation that gets the token through the module's pre-build hook:" \
  "  nix build .#checks.x86_64-linux.vm -L"
