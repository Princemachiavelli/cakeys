#!/usr/bin/env bash
# The Google Cloud KMS test bed (docs/CLOUD_HSM.md, "Google Cloud KMS"): libkmsp11 runs here, no
# VM, against one key ring of pre-created keys. The infrastructure is scripts/cloud/gcp/main.tf.
#
#   scripts/cloud/gcp.sh create
#   scripts/cloud/gcp.sh probe [--write]
#   scripts/cloud/gcp.sh cakeys <cakeys arguments>
#   scripts/cloud/gcp.sh status
#   scripts/cloud/gcp.sh destroy
#
# create    enables the Cloud KMS API (gcloud) and creates the key ring `caprobe` and one key per algorithm of
#           the kmsp11 provider's table (crates/kmsp11/src/keys.json), each with no version and a
#           24-hour destroy-scheduled duration. Free: nothing bills until a version exists.
# probe     runs caprobe through both libkmsp11 builds, .#kmsp11 and .#kmsp11-fips (FIPS mode
#           required), one after the other. Read-only by default: the token, its mechanisms, no
#           key. With --write, each build adds one version to every key, probes it and destroys
#           it (24 hours scheduled, then gone), into profiles/modules/kmsp11/<ver>+hsm.toml and
#           <ver>+hsm-fips.toml; an existing profile is diffed (exit 15 on drift, the file
#           rewritten anyway). --write first checks that every key in the table exists here
#           with the 24-hour duration: libkmsp11 would create a missing one with the 30-day
#           default. CAPROBE names a caprobe binary to use instead of building one.
# cakeys    runs cakeys with scripts/cloud/gcp/cakeys.toml (its keys pre-created by create, 24 hours,
#           no version) and a lock in the state directory: `cakeys create`, `verify ec-p256
#           --token gcp`, `delete ...`. CAKEYS names a cakeys binary to use instead of building one.
# status    lists the versions under the ring's keys that are not destroyed or scheduled for
#           destruction (those bill), and exits 1 while any exist.
# destroy   schedules every such version for destruction: what an interrupted probe left. The
#           ring and the keys stay; they are free, and Cloud KMS keeps them until every version
#           is destroyed.
#
# CAKEYS_GCP_PROJECT (required) and CAKEYS_GCP_LOCATION (default us-west1) say where. gcloud
# uses its own login; OpenTofu and libkmsp11 use Application Default Credentials:
# GOOGLE_APPLICATION_CREDENTIALS, else gcloud's ADC file, else the active account's copy
# gcloud keeps under legacy_credentials. The OpenTofu state lives in
# ${XDG_STATE_HOME:-~/.local/state}/cakeys/cloud/gcp, outside the worktree.
set -euo pipefail
shopt -s inherit_errexit

repo=$(realpath "$(dirname "$(realpath "$0")")/../..")
tf=$repo/scripts/cloud/gcp
state=${XDG_STATE_HOME:-$HOME/.local/state}/cakeys/cloud/gcp
project=${CAKEYS_GCP_PROJECT:?the GCP project id}
location=${CAKEYS_GCP_LOCATION:-us-west1}
ring=projects/$project/locations/$location/keyRings/caprobe
export TF_DATA_DIR=$state/.terraform TF_IN_AUTOMATION=1 TF_INPUT=0
export CLOUDSDK_CORE_PROJECT=$project

usage() {
  sed -n '/^#   scripts/s/^#   //p' "$0" >&2
  exit 2
}

tools=$(nix build --no-link --print-out-paths "$repo#cloud-tools")
PATH=$tools/bin:$PATH
mkdir -p "$state"

if [[ -z ${GOOGLE_APPLICATION_CREDENTIALS-} ]]; then
  adc=$HOME/.config/gcloud/application_default_credentials.json
  [[ -r $adc ]] || adc=$HOME/.config/gcloud/legacy_credentials/$(gcloud config get-value account 2>/dev/null)/adc.json
  [[ -r $adc ]] || {
    echo "no Application Default Credentials: run 'gcloud auth application-default login'" >&2
    exit 1
  }
  export GOOGLE_APPLICATION_CREDENTIALS=$adc
fi

tofu() { command tofu -chdir="$tf" "$@"; }

tf_init() {
  tofu init -input=false -backend-config="path=$state/terraform.tfstate" >/dev/null
}

# The probe's labels: the table's probe rows (it holds every algorithm cakeys may ask for).
labels() {
  jq -r '.[] | select(.probe) | .algorithm | ascii_downcase | gsub("_"; "-") | "caprobe-" + .' \
    "$repo/crates/kmsp11/src/keys.json"
}

# The versions under any key of the ring that bill: neither destroyed nor scheduled for
# destruction (the probe's keys and cakeys.toml's).
live_versions() {
  local key
  for key in $(gcloud kms keys list --keyring caprobe --location "$location" --format 'value(name.basename())'); do
    gcloud kms keys versions list --key "$key" --keyring caprobe --location "$location" \
      --filter 'state!=DESTROYED AND state!=DESTROY_SCHEDULED' --format 'value(name,state)' 2>/dev/null || true
  done
}

create() {
  gcloud services enable cloudkms.googleapis.com
  tf_init
  tofu apply -input=false -auto-approve -var "project=$project" -var "location=$location"
}

# Refuse a write probe unless every key libkmsp11 will be asked for exists, with 24 hours.
preflight() {
  local have missing
  have=$(gcloud kms keys list --keyring caprobe --location "$location" --format json |
    jq -r '.[] | select(.destroyScheduledDuration == "86400s") | .name | split("/") | last')
  missing=$(comm -23 <(labels | sort) <(sort <<<"$have"))
  if [[ -n $missing ]]; then
    echo "refusing: these keys are missing or lack the 24-hour destroy duration;" \
      "run '$0 create' first:" >&2
    echo "$missing" >&2
    exit 1
  fi
}

# libkmsp11's config for one build ($1: kmsp11 or kmsp11-fips), written to the state directory;
# prints its path. Versions go into pre-created keys (experimental_create_multiple_versions).
kms_config() {
  local cfg=$state/$1.yaml
  # libkmsp11 refuses a config file anyone but its owner can write.
  (
    umask 077
    cat >"$cfg" <<EOF
tokens:
  - key_ring: "$ring"
    label: "caprobe"
user_project_override: "$project"
experimental_create_multiple_versions: true
log_directory: "$state"
EOF
    if [[ $1 == kmsp11-fips ]]; then
      echo "require_fips_mode: true" >>"$cfg"
    fi
  )
  echo "$cfg"
}

# cakeys against the ring with scripts/cloud/gcp/cakeys.toml and a lock in the state directory:
# every argument goes to cakeys. CAKEYS names a cakeys binary to use instead of building one,
# CAKEYS_GCP_LOCK another lock (crates/cli/tests/cloud.rs: one per run).
cakeys() {
  local bin lib
  bin=${CAKEYS:-$(nix build --no-link --print-out-paths --impure --expr \
    "((builtins.getFlake \"git+file://$repo\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; })")/bin/cakeys}
  lib=$(nix build --no-link --print-out-paths "$repo#kmsp11")
  echo unused >"$state/pin"
  KMS_PKCS11_CONFIG=$(kms_config kmsp11) CAKEYS_GCP_PIN=$state/pin "$bin" \
    --config "$tf/../gcp/cakeys.toml" --lock "${CAKEYS_GCP_LOCK:-$state/cakeys.lock}" --module "gcp=$lib/lib/libkmsp11.so" "$@"
}

probe() {
  local write=0
  while (($#)); do
    case $1 in
    --write) write=1 ;;
    *) usage ;;
    esac
    shift
  done
  ((write)) && preflight
  local bin variant lib name out cfg rc=0 status=0
  bin=${CAPROBE:-$(nix build --no-link --print-out-paths --impure --expr \
    "((builtins.getFlake \"git+file://$repo\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; }).caprobe")/bin/caprobe}
  echo unused >"$state/pin"
  for variant in kmsp11 kmsp11-fips; do
    lib=$(nix build --no-link --print-out-paths "$repo#$variant")
    name=kmsp11/$(sed -E 's/.*-([0-9]+\.[0-9]+)$/\1/' <<<"$lib")+hsm${variant#kmsp11}
    cfg=$(kms_config "$variant")
    cat >"$state/keys.toml" <<EOF
[tokens.gcp]
module = "$lib/lib/libkmsp11.so"
tokenLabel = "caprobe"
# libkmsp11 ignores the PIN; caprobe wants a login all the same.
pinFile = "$state/pin"
probe = { scratch = true }
EOF
    local -a args=(--config "$state/keys.toml" probe --profiles "$repo/profiles" --token gcp --name "$name")
    if ((write)); then
      out=$repo/profiles/modules/$name.toml
      mkdir -p "$(dirname "$out")"
      args+=(--write --out "$out")
      [[ -f $out ]] && args+=(--diff "$name")
    else
      out=$state/${variant}-read-only.toml
      args+=(--out "$out")
    fi
    echo "== $variant: $name"
    rc=0
    KMS_PKCS11_CONFIG=$cfg "$bin" "${args[@]}" || rc=$?
    [[ $rc == 0 || $rc == 15 ]] || status=$rc
    echo "wrote $out (exit $rc)"
  done
  if ((write)) && [[ -n $(live_versions) ]]; then
    echo "versions still live (billing): run '$0 destroy'" >&2
    live_versions >&2
    status=1
  fi
  return "$status"
}

status() {
  local live
  live=$(live_versions)
  echo "probe key versions that bill in $ring:"
  local v
  while read -r v; do
    echo "  ${v:-none}"
  done <<<"$live"
  [[ -z $live ]]
}

destroy() {
  local name state
  live_versions | while read -r name state; do
    gcloud kms keys versions destroy "$name" --quiet --format 'value(name,state)'
  done
}

(($#)) || usage
cmd=$1
shift
case $cmd in
create) create "$@" ;;
probe) probe "$@" ;;
cakeys) cakeys "$@" ;;
status) status "$@" ;;
destroy) destroy "$@" ;;
*) usage ;;
esac
