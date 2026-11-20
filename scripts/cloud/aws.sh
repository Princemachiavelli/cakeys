#!/usr/bin/env bash
# Create and destroy the AWS CloudHSM test bed (docs/CLOUD_HSM.md, "AWS CloudHSM"): a VPC in
# us-west-1, a CloudHSM cluster with one HSM, and a NixOS runner in the cluster's security group.
# The infrastructure is scripts/cloud/aws/main.tf; this script runs OpenTofu on it.
#
#   scripts/cloud/aws.sh create [--hsm-type T] [--instance-type T] [--nixos R]
#   scripts/cloud/aws.sh init
#   scripts/cloud/aws.sh activate
#   scripts/cloud/aws.sh probe [<profile name>]
#   scripts/cloud/aws.sh cakeys <cakeys arguments>
#   scripts/cloud/aws.sh camigrate <camigrate arguments>
#   scripts/cloud/aws.sh destroy [--park] [--yes]
#   scripts/cloud/aws.sh status
#
# create    brings everything up and prints the runner's address and the HSM's IP. The cluster is
#           left as AWS made it (UNINITIALIZED on first create). The flags are remembered: a
#           later create needs none.
# init      signs the cluster's CSR with a root CA of our own, made on first use and kept with
#           its (unencrypted) key in the state directory, and initializes the cluster.
# activate  sets the runner's CloudHSM CLI and PKCS#11 library up under /opt/cloudhsm (one HSM:
#           key availability check off; raw ECDH, CKD_NULL, on: the client refuses it otherwise),
#           activates the cluster, and creates the crypto user
#           caprobe logs in as. The passwords are made on first use and kept in the state
#           directory; they reach the runner on SSH's stdin.
# probe     copies the Nix-built caprobe and the PKCS#11 library to the runner and runs a write
#           probe as the crypto user, into profiles/modules/<name>.toml (default
#           aws-cloudhsm/<major.minor>+hsm2m-fips or -non-fips). An existing profile is diffed
#           (exit 15 on drift, the file rewritten anyway). CAPROBE names a caprobe binary to use
#           instead of building one.
# cakeys    runs cakeys on the runner with scripts/cloud/aws/cakeys.toml, the crypto user's PIN in
#           tmpfs and a lock kept on the runner, against CloudHSM and a SoftHSM token beside it:
#           `cakeys create`, `verify ec-p256 --token cloudhsm`, `delete ...`. CAKEYS names a
#           cakeys binary to use instead of building one; CAKEYS_AWS_CONFIG another keys.toml,
#           CAKEYS_AWS_LOCK another lock path on the runner (crates/cli/tests/cloud.rs: one per run).
# camigrate the same for camigrate (CAMIGRATE): `camigrate migrate movable --from softhsm --to
#           cloudhsm`, and back: `migrate outbound --from cloudhsm --to softhsm`.
# destroy   deletes everything: HSM, runner, cluster, the cluster's backups (AWS keeps them in
#           PENDING_DELETION for 7 days; `aws cloudhsmv2 restore-backup` brings one back), and
#           the network. An initialized cluster also needs --yes.
#   --park  deletes only the HSM and the runner. Deleting the last HSM backs the cluster up; the
#           next create makes an HSM in the same cluster, which restores that backup. A parked
#           cluster bills nothing by the hour.
# status    lists every CloudHSM cluster and caprobe-tagged instance in the region with what it
#           bills, and exits 1 while anything billed by the hour exists.
#
# create and destroy --park refuse a plan that would delete the cluster (a changed --hsm-type,
# for one): that would lose its initialization. Run a full destroy first if that is meant.
#
# CAKEYS_AWS_MODE (FIPS, the default, or NON_FIPS) picks the cluster: one per mode, since a
# cluster's mode is fixed for its life. Each has its own network, CA, users and state.
#
# Credentials: the AWS CLI's usual chain (AWS_PROFILE, `aws login`, `aws sso login`). The region
# is always us-west-1, whatever the profile says. The OpenTofu state lives in
# ${XDG_STATE_HOME:-~/.local/state}/cakeys/cloud/aws/<fips|non-fips>, outside the worktree:
# losing it leaves billed resources nothing knows about (`status` still finds them).
#
# SSH_PUBLIC_KEY_FILE (default ~/.ssh/id_ed25519.pub) is the key the runner's root accepts; port
# 22 is open to this machine's current public address only, re-read at every create.

# Backticks in the --query strings are JMESPath literals, not command substitutions.
# shellcheck disable=SC2016
set -euo pipefail
shopt -s inherit_errexit

repo=$(realpath "$(dirname "$(realpath "$0")")/../..")
tf=$repo/scripts/cloud/aws
mode=${CAKEYS_AWS_MODE:-FIPS}
case $mode in
FIPS | NON_FIPS) ;;
*)
  echo "CAKEYS_AWS_MODE is FIPS or NON_FIPS, not '$mode'" >&2
  exit 2
  ;;
esac
stack=$(tr '[:upper:]_' '[:lower:]-' <<<"$mode")
state=${XDG_STATE_HOME:-$HOME/.local/state}/cakeys/cloud/aws/$stack
vars=$state/vars.tfvars.json
export AWS_REGION=us-west-1 AWS_DEFAULT_REGION=us-west-1
export TF_DATA_DIR=$state/.terraform TF_IN_AUTOMATION=1 TF_INPUT=0

usage() {
  sed -n '/^#   scripts/s/^#   //p' "$0" >&2
  exit 2
}

tools=$(nix build --no-link --print-out-paths "$repo#cloud-tools")
PATH=$tools/bin:$PATH
mkdir -p "$state"
[[ -f $vars ]] || echo '{}' >"$vars"

tofu() { command tofu -chdir="$tf" "$@"; }

tf_init() {
  tofu init -input=false -backend-config="path=$state/terraform.tfstate" >/dev/null
}

# An output's value, empty when the state has no such output (yet). Read from `output -json`:
# `output -raw` exits 0 and prints a warning to stdout when the state has no outputs, and fails
# alike for a missing output and a broken state. A failing OpenTofu (a broken state or backend)
# is shown and fails, rather than leaving an empty host or ID for a later command to trip over.
out() { tofu output -json | jq -r --arg name "$1" '.[$name].value // empty'; }

pkg() { nix build --no-link --print-out-paths "$repo#$1"; }

# The runner: root over SSH with the operator's key alone (an agent holding many keys runs into
# sshd's MaxAuthTries), and a known_hosts file per instance.
sshopts() {
  local key=${SSH_PUBLIC_KEY_FILE:-$HOME/.ssh/id_ed25519.pub}
  printf '%s\n' -o IdentitiesOnly=yes -i "$key" -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$state/known_hosts.$(out runner_ip)" -o ConnectTimeout=10
}

# Run a command on the runner; its words are expanded here, by design.
runner() {
  local opts
  local -a o
  opts=$(sshopts)
  mapfile -t o <<<"$opts"
  # shellcheck disable=SC2029
  ssh "${o[@]}" "root@$(out runner_ip)" "$@"
}

# Copy store paths, with their closures, into the runner's store. What this machine built carries
# no cache signature; root is a trusted user there, so the runner takes it unsigned.
copy() {
  local opts
  opts=$(sshopts)
  NIX_SSHOPTS=${opts//$'\n'/ } nix copy --no-check-sigs --to "ssh-ng://root@$(out runner_ip)" "$@"
}

wait_runner() {
  for _ in $(seq 30); do
    runner true 2>/dev/null && return
    sleep 10
  done
  echo "runner root@$(out runner_ip) does not answer on SSH" >&2
  exit 1
}

# A password kept in the state directory, made on first use: hex, so no character the CLI or a
# shell treats specially (CloudHSM forbids ':').
secret() {
  local f=$state/secrets/$1
  [[ -s $f ]] || (
    umask 077
    mkdir -p "$state/secrets"
    openssl rand -hex 12 >"$f"
  )
  cat "$f"
}

wait_state() {
  local cid=$1 want=$2 st
  for _ in $(seq 120); do
    st=$(cluster_state "$cid")
    if [[ $st == "$want" ]]; then
      echo "cluster $cid is $st"
      return
    fi
    sleep 15
  done
  echo "cluster $cid is still $st after 30 minutes, not $want" >&2
  exit 1
}

# Plan with the given var file and extra arguments, refuse a plan that deletes the cluster,
# remember the var file, apply. Remembered before the apply: an apply that fails halfway still
# leaves destroy the values it planned with.
apply_guarded() {
  local varfile=$1 plan=$state/plan
  shift
  tofu plan -input=false -out="$plan" -var-file="$varfile" "$@"
  if ! tofu show -json "$plan" | jq -e '
      [.resource_changes[]? | select(.address == "aws_cloudhsm_v2_cluster.this")
        | select(.change.actions | index("delete"))] | length == 0' >/dev/null; then
    echo "refusing: this plan deletes the CloudHSM cluster; the attributes that force it:" >&2
    tofu show -json "$plan" | jq -c '.resource_changes[]
      | select(.address == "aws_cloudhsm_v2_cluster.this") | .change.replace_paths' >&2
    echo "run '$0 destroy' first if a new cluster is meant" >&2
    rm -f "$plan"
    exit 1
  fi
  [[ $varfile == "$vars" ]] || mv "$varfile" "$vars"
  tofu apply -input=false "$plan"
  rm -f "$plan"
}

cluster_state() {
  aws cloudhsmv2 describe-clusters --filters "clusterIds=$1" \
    --query 'Clusters[0].State' --output text
}

create() {
  local next=$state/next.tfvars.json key=${SSH_PUBLIC_KEY_FILE:-$HOME/.ssh/id_ed25519.pub} ip
  local -a set=(--arg mode "$mode" --arg stack "$stack")
  while (($#)); do
    case $1 in
    --hsm-type) set+=(--arg hsm_type "${2-}") ;;
    --instance-type) set+=(--arg instance_type "${2-}") ;;
    --nixos) set+=(--arg nixos_release "${2-}") ;;
    *) usage ;;
    esac
    [[ -n ${2-} ]] || usage
    shift 2
  done
  [[ -r $key ]] || {
    echo "no SSH public key at $key (set SSH_PUBLIC_KEY_FILE)" >&2
    exit 1
  }
  ip=$(curl -sf https://checkip.amazonaws.com)
  # $ARGS.named holds jq's --arg pairs: merged over what an earlier create used. The key, the
  # address and the expiry are re-read at every create; destroy only replays them.
  jq "${set[@]}" --arg ssh_public_key "$(<"$key")" --arg ssh_cidr "$ip/32" \
    --arg expires "$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)" \
    '. + $ARGS.named' "$vars" >"$next"
  tf_init
  apply_guarded "$next" -var park=false
  local cid
  cid=$(out cluster_id) ip=$(out runner_ip)
  cat <<EOF

cluster   $cid ($(out mode), $(cluster_state "$cid"))
hsm       $(out hsm_ip)
runner    root@$ip ($(out runner_ami))
          ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $key root@$ip
billing   the HSM at \$1.81/h until '$0 destroy [--park]'
EOF
}

init() {
  tf_init
  local cid ca=$state/ca st
  cid=$(out cluster_id)
  [[ -n $cid ]] || {
    echo "no cluster: run '$0 create'" >&2
    exit 1
  }
  st=$(cluster_state "$cid")
  case $st in
  INITIALIZED | ACTIVE)
    echo "cluster $cid is already $st"
    return
    ;;
  UNINITIALIZED) ;;
  *)
    echo "cluster $cid is $st; init needs UNINITIALIZED, with an HSM in it" >&2
    exit 1
    ;;
  esac
  mkdir -p "$ca"
  chmod 700 "$ca"
  [[ -f $ca/customerCA.key ]] || (
    umask 077
    openssl genrsa -out "$ca/customerCA.key" 2048
  )
  [[ -f $ca/customerCA.crt ]] || openssl req -new -x509 -days 3652 -key "$ca/customerCA.key" \
    -subj "/CN=caprobe CloudHSM test root" -out "$ca/customerCA.crt"
  aws cloudhsmv2 describe-clusters --filters "clusterIds=$cid" \
    --query 'Clusters[0].Certificates.ClusterCsr' --output text >"$ca/$cid.csr"
  openssl x509 -req -days 3652 -in "$ca/$cid.csr" -CA "$ca/customerCA.crt" \
    -CAkey "$ca/customerCA.key" -CAcreateserial -out "$ca/$cid.crt"
  aws cloudhsmv2 initialize-cluster --cluster-id "$cid" --signed-cert "file://$ca/$cid.crt" \
    --trust-anchor "file://$ca/customerCA.crt" --query State --output text
  wait_state "$cid" INITIALIZED
}

activate() {
  tf_init
  local cid hsm cli p11 admin cu
  cid=$(out cluster_id) hsm=$(out hsm_ip)
  [[ -n $hsm && -n $(out runner_ip) ]] || {
    echo "no HSM or no runner: run '$0 create'" >&2
    exit 1
  }
  [[ -f $state/ca/customerCA.crt ]] || {
    echo "no trust anchor: run '$0 init'" >&2
    exit 1
  }
  cli=$(pkg cloudhsm-cli) p11=$(pkg cloudhsm-pkcs11)
  wait_runner
  copy "$cli" "$p11"
  admin=$(secret admin) cu=$(secret cu)
  runner install -D -m 644 /dev/stdin /opt/cloudhsm/etc/customerCA.crt <"$state/ca/customerCA.crt"
  # The configure tools edit only /opt/cloudhsm/etc/<tool>.cfg, which must exist: AWS's templates.
  runner bash -s <<EOF
set -euo pipefail
mkdir -p /opt/cloudhsm/run
install -m 644 $cli/etc/cloudhsm-cli.cfg $p11/etc/cloudhsm-pkcs11.cfg /opt/cloudhsm/etc/
$cli/bin/configure-cli -a $hsm --disable-key-availability-check
$p11/bin/configure-pkcs11 -a $hsm --disable-key-availability-check --enable-ecdh-without-kdf
EOF
  # The passwords travel inside the script on stdin, never in ssh's own command line; on the
  # runner they are cloudhsm-cli arguments for as long as it runs.
  if [[ $(cluster_state "$cid") != ACTIVE ]]; then
    runner bash -s <<EOF
set -euo pipefail
$cli/bin/cloudhsm-cli cluster activate --password '$admin'
EOF
    wait_state "$cid" ACTIVE
  fi
  runner bash -s <<EOF
set -euo pipefail
export CLOUDHSM_ROLE=admin CLOUDHSM_PIN='admin:$admin'
if ! $cli/bin/cloudhsm-cli user list | grep -q '"username": "caprobe"'; then
  $cli/bin/cloudhsm-cli user create --username caprobe --role crypto-user --password '$cu'
fi
$cli/bin/cloudhsm-cli user list
EOF
}

# The module profile of this cluster's mode for the client package $1: aws-cloudhsm/<major.minor>
# +hsm2m-fips or -non-fips. The two tie on every match key (PKCS#11 reports no mode, D12), so
# `cakeys` and `camigrate` pin it as the cloudhsm token's moduleProfile.
profile_name() {
  echo "aws-cloudhsm/$(sed -E 's/.*-([0-9]+\.[0-9]+)\.[0-9]+$/\1/' <<<"$1")+hsm2m-$stack"
}

probe() {
  tf_init
  local p11 opensc bin label name out rc=0
  p11=$(pkg cloudhsm-pkcs11)
  name=${1:-$(profile_name "$p11")}
  out=$repo/profiles/modules/$name.toml
  opensc=$(nix build --no-link --print-out-paths --inputs-from "$repo" nixpkgs#opensc)
  # Only the Nix-built caprobe may write a profile (docs/CAPROBE.md); its check phase is skipped
  # as scripts/regen-profiles.sh does.
  bin=${CAPROBE:-$(nix build --no-link --print-out-paths --impure --expr \
    "((builtins.getFlake \"git+file://$repo\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; }).caprobe")/bin/caprobe}
  wait_runner
  copy "$p11" "$opensc" "$(dirname "$(dirname "$(realpath "$bin")")")"
  label=$(runner "$opensc/bin/pkcs11-tool" --module "$p11/lib/libcloudhsm_pkcs11.so" -L |
    sed -n 's/^ *token label *: *//p' | sed 's/ *$//;q')
  echo "token label: $label"
  # The PIN leaves the runner however this ends: a failing step below exits under errexit,
  # where a RETURN trap or the `rm` after the probe would not run.
  trap 'runner rm -f /run/caprobe/pin || true' EXIT
  runner install -D -m 600 /dev/stdin /run/caprobe/pin <<<"caprobe:$(secret cu)"
  runner install -D -m 644 /dev/stdin /run/caprobe/keys.toml <<EOF
[tokens.cloudhsm]
module = "$p11/lib/libcloudhsm_pkcs11.so"
tokenLabel = "$label"
pinFile = "/run/caprobe/pin"
probe = { scratch = true }
EOF
  # The checkout's profiles, as scripts/regen-profiles.sh passes them: --diff finds the committed
  # one even before the binary embeds it.
  runner rm -rf /run/caprobe/profiles
  tar -C "$repo" -c profiles | runner tar -C /run/caprobe -x
  local -a diff=()
  [[ -f $out ]] && diff=(--diff "$name")
  # caprobe keeps the [migration] and [manual] sections of the file it overwrites: the
  # committed one, in place for it.
  runner rm -f /run/caprobe/profile.toml
  if [[ -f $out ]]; then
    runner install -D -m 644 /dev/stdin /run/caprobe/profile.toml <"$out"
  fi
  runner "$(realpath "$bin")" --config /run/caprobe/keys.toml probe --profiles /run/caprobe/profiles \
    --token cloudhsm --write --name "$name" "${diff[@]}" --out /run/caprobe/profile.toml || rc=$?
  runner rm -f /run/caprobe/pin
  # 15 is drift against the committed profile: written anyway, for review.
  [[ $rc == 0 || $rc == 15 ]] || exit "$rc"
  mkdir -p "$(dirname "$out")"
  runner cat /run/caprobe/profile.toml >"$out"
  echo "wrote $out"
  return "$rc"
}

# cakeys on the runner with scripts/cloud/aws/cakeys.toml, the crypto user's PIN in tmpfs and a
# lock that stays on the runner: every argument goes to cakeys.
cakeys() { tool cakeys "${CAKEYS-}" "$@"; }
camigrate() { tool camigrate "${CAMIGRATE-}" "$@"; }

# cakeys or camigrate ($1; $2 a binary to use instead of building it) on the runner, against
# CloudHSM and a SoftHSM token beside it (made on first use, PIN 1234), with
# scripts/cloud/aws/cakeys.toml, the crypto user's PIN in tmpfs and a lock kept on the runner.
tool() {
  local name=$1 bin=$2 p11 softhsm args
  shift 2
  tf_init
  p11=$(pkg cloudhsm-pkcs11)
  softhsm=$(nix build --no-link --print-out-paths --inputs-from "$repo" nixpkgs#softhsm)
  if [[ -z $bin ]]; then
    local out=out
    [[ $name == cakeys ]] || out=$name
    bin=$(nix build --no-link --print-out-paths --impure --expr \
      "((builtins.getFlake \"git+file://$repo\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; }).$out")/bin/$name
  fi
  bin=$(realpath "$bin")
  wait_runner
  copy "$p11" "$softhsm" "$(dirname "$(dirname "$bin")")"
  # Written for this run and removed when the script exits, whatever happens on the way.
  trap 'runner rm -f /run/cakeys/pin || true' EXIT
  runner install -D -m 600 /dev/stdin /run/cakeys/pin <<<"caprobe:$(secret cu)"
  sed "s|^\[tokens.cloudhsm\]\$|&\nmoduleProfile = \"$(profile_name "$p11")\"|" "${CAKEYS_AWS_CONFIG:-$tf/cakeys.toml}" |
    runner install -D -m 644 /dev/stdin /root/cakeys/keys.toml
  runner bash -s <<EOF
set -euo pipefail
mkdir -p /root/softhsm/tokens "$(dirname "${CAKEYS_AWS_LOCK:-/root/cakeys/keys.lock}")"
echo 1234 >/root/softhsm/pin
printf 'directories.tokendir = /root/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' >/root/softhsm/softhsm2.conf
export SOFTHSM2_CONF=/root/softhsm/softhsm2.conf
$softhsm/bin/softhsm2-util --show-slots | grep -q 'Label:.*kmtest' ||
  $softhsm/bin/softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678 >/dev/null
EOF
  printf -v args '%q ' "$@"
  runner "CAKEYS_AWS_PIN=/run/cakeys/pin SOFTHSM2_CONF=/root/softhsm/softhsm2.conf $bin" \
    "--config /root/cakeys/keys.toml --lock ${CAKEYS_AWS_LOCK:-/root/cakeys/keys.lock}" \
    "--module cloudhsm=$p11/lib/libcloudhsm_pkcs11.so --module softhsm=$softhsm/lib/softhsm/libsofthsm2.so $args"
}

destroy() {
  local park=0 yes=0
  while (($#)); do
    case $1 in
    --park) park=1 ;;
    --yes) yes=1 ;;
    *) usage ;;
    esac
    shift
  done
  tf_init
  if [[ -z $(tofu state list 2>/dev/null) ]]; then
    echo "nothing in $state/terraform.tfstate; '$0 status' lists what the region holds"
    return
  fi
  if ((park)); then
    apply_guarded "$vars" -var park=true
    echo "parked: cluster $(out cluster_id) kept; no HSM, no runner"
    return
  fi
  # Kept until the end: a destroy cut short after the cluster went still finds its backups.
  local cidf=$state/destroyed-cluster cid cs
  cid=$(out cluster_id)
  if [[ -n $cid ]]; then
    cs=$(cluster_state "$cid")
    if [[ $cs != UNINITIALIZED && $cs != None ]] && ((! yes)); then
      echo "cluster $cid is $cs: a full destroy loses its initialization;" \
        "add --yes, or use --park" >&2
      exit 1
    fi
    echo "$cid" >"$cidf"
  fi
  local vpc sg b
  # The cluster and what depends on it (HSM, runner) first, so the security group create-cluster
  # made can go before the VPC does.
  tofu destroy -input=false -auto-approve -var-file="$vars" -target=aws_cloudhsm_v2_cluster.this
  vpc=$(out vpc_id)
  if [[ -n $vpc ]]; then
    for sg in $(aws ec2 describe-security-groups \
      --filters "Name=vpc-id,Values=$vpc" 'Name=group-name,Values=cloudhsm-cluster-*' \
      --query 'SecurityGroups[].GroupId' --output text); do
      aws ec2 delete-security-group --group-id "$sg"
    done
  fi
  if [[ -s $cidf ]]; then
    for b in $(aws cloudhsmv2 describe-backups --filters "clusterIds=$(<"$cidf")" \
      --query 'Backups[?BackupState!=`PENDING_DELETION`].BackupId' --output text); do
      aws cloudhsmv2 delete-backup --backup-id "$b" >/dev/null
      echo "backup $b: pending deletion for 7 days (aws cloudhsmv2 restore-backup --backup-id $b)"
    done
  fi
  tofu destroy -input=false -auto-approve -var-file="$vars"
  rm -f "$cidf"
  echo '{}' >"$vars"
}

status() {
  local live='Name=instance-state-name,Values=pending,running,stopping,stopped'
  local hsms instances
  echo "CloudHSM clusters in $AWS_REGION (\$1.81/h per HSM):"
  aws cloudhsmv2 describe-clusters \
    --query 'Clusters[].[ClusterId, State, Mode, length(Hsms)]' --output text |
    while read -r id st mode n; do
      printf '  %s  %-14s %-8s %s HSM\n' "$id" "$st" "$mode" "$n"
    done
  echo "caprobe instances:"
  aws ec2 describe-instances --filters Name=tag:caprobe,Values=1 "$live" \
    --query 'Reservations[].Instances[].[InstanceId, InstanceType, State.Name, PublicIpAddress, Tags[?Key==`expires`]|[0].Value]' \
    --output text | while read -r id ty st ip exp; do
    printf '  %s  %-10s %-8s %-15s expires %s\n' "$id" "$ty" "$st" "$ip" "$exp"
  done
  hsms=$(aws cloudhsmv2 describe-clusters --query 'sum(Clusters[].length(Hsms))' --output text)
  instances=$(aws ec2 describe-instances --filters Name=tag:caprobe,Values=1 "$live" \
    --query 'length(Reservations[].Instances[])' --output text)
  ((hsms == 0 && instances == 0))
}

(($#)) || usage
cmd=$1
shift
case $cmd in
create) create "$@" ;;
init) init "$@" ;;
activate) activate "$@" ;;
probe) probe "$@" ;;
cakeys) cakeys "$@" ;;
camigrate) camigrate "$@" ;;
destroy) destroy "$@" ;;
status) status "$@" ;;
*) usage ;;
esac
