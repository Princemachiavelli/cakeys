# cakeys pre-build-hook: give a build the sandbox paths of the tokens whose system feature it
# requires, and nothing to any other build.
#
# Called by nix-daemon (as root) for every sandboxed build: $1 = .drv path, $2 = sandbox dir.
# The token map ({ "<feature>": ["/path" | "/target=/source", ...] }) comes from the NixOS module
# in $CAKEYS_SANDBOX_MAP. Paths only ever come from that map; the derivation merely selects entries.
#
# Contract: always exit 0, and stdout carries only the hook protocol. A non-zero exit or a stray
# line would fail *every* build on the host. Any error grants nothing, so a build that needed a
# token fails later for lack of access. Recovery if this hook misbehaves:
#   nix build --option pre-build-hook "" ...   (trusted users)

# Features from a plain derivation (env string), structured attrs (Nix >= 2.33 JSON v4), or
# structured attrs in older JSON (env.__json); `nix derivation show` keys the drv either way.
# shellcheck disable=SC2016 # a jq program, not shell
features_filter='
  (if has("derivations") then .derivations else . end) | to_entries | first.value
  | [ (.structuredAttrs.requiredSystemFeatures? // [])[],
      ((.env.requiredSystemFeatures // "") | splits("[ \t\n]+")),
      ((.env.__json // "{}") | fromjson | (.requiredSystemFeatures // [])[]) ]
  | map(select(. != "")) | unique as $features
  | $map[0] | to_entries[] | select(.key as $k | $features | index($k)) | .value[]
'

grant() {
  local drv=$1 entries entry out=""
  # Only ever a store derivation (an empty or other argument would be read as an installable).
  case $drv in /*.drv) ;; *) return 0 ;; esac
  entries=$(nix --extra-experimental-features nix-command derivation show "$drv" |
    jq -r --slurpfile map "$CAKEYS_SANDBOX_MAP" "$features_filter") || return 0
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    # No `?` (optional) in the hook protocol: only grant what exists, or the build fails to start.
    if [ -e "${entry#*=}" ]; then
      out+="$entry"$'\n'
    else
      echo "cakeys-sandbox-hook: ${entry#*=} does not exist; not granted to $drv" >&2
    fi
  done <<<"$entries"
  if [ -n "$out" ]; then
    printf 'extra-sandbox-paths\n%s\n' "$out"
  fi
}

grant "${1:-}" || true
exit 0
