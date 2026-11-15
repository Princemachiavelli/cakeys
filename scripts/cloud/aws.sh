#!/usr/bin/env bash
# Create and destroy the AWS CloudHSM test bed (docs/CLOUD_HSM.md, "AWS CloudHSM"): a VPC in
# us-west-1, a CloudHSM cluster with one HSM, and a NixOS runner in the cluster's security group.
# The infrastructure is scripts/cloud/aws/main.tf; this script runs OpenTofu on it.
#
#   scripts/cloud/aws.sh create [--mode FIPS|NON_FIPS] [--hsm-type T] [--instance-type T] [--nixos R]
#   scripts/cloud/aws.sh init
#   scripts/cloud/aws.sh activate
#   scripts/cloud/aws.sh probe [<profile name>]
#   scripts/cloud/aws.sh destroy [--park] [--yes]
#   scripts/cloud/aws.sh status
#
# create    brings everything up and prints the runner's address and the HSM's IP. The cluster is
#           left as AWS made it (UNINITIALIZED on first create). The flags are remembered: a
#           later create needs none.
# init      signs the cluster's CSR with a root CA of our own, made on first use and kept with
#           its (unencrypted) key in the state directory, and initializes the cluster.
# activate  sets the runner's CloudHSM CLI and PKCS#11 library up under /opt/cloudhsm (one HSM:
#           key availability check off), activates the cluster, and creates the crypto user
#           caprobe logs in as. The passwords are made on first use and kept in the state
#           directory; they reach the runner on SSH's stdin.
# probe     copies the Nix-built caprobe and the PKCS#11 library to the runner and runs a write
#           probe as the crypto user, into profiles/modules/<name>.toml (default
#           cloudhsm-pkcs11/<major.minor>+hsm2m-fips or -non-fips). An existing profile is diffed
#           (exit 15 on drift, the file rewritten anyway). CAPROBE names a caprobe binary to use
#           instead of building one.
# destroy   deletes everything: HSM, runner, cluster, the cluster's backups (AWS keeps them in
#           PENDING_DELETION for 7 days; `aws cloudhsmv2 restore-backup` brings one back), and
#           the network. An initialized cluster also needs --yes.
#   --park  deletes only the HSM and the runner. Deleting the last HSM backs the cluster up; the
#           next create makes an HSM in the same cluster, which restores that backup. A parked
#           cluster bills nothing by the hour.
# status    lists every CloudHSM cluster and caprobe-tagged instance in the region with what it
#           bills, and exits 1 while anything billed by the hour exists.
#
# create and destroy --park refuse a plan that would delete the cluster (a changed --mode, for
# one): that would lose its initialization. Run a full destroy first if that is meant.
#
# Credentials: the AWS CLI's usual chain (AWS_PROFILE, `aws login`, `aws sso login`). The region
# is always us-west-1, whatever the profile says. The OpenTofu state lives in
# ${XDG_STATE_HOME:-~/.local/state}/cakeys/cloud/aws, outside the worktree: losing it leaves
# billed resources nothing knows about (`status` still finds them).
#
# SSH_PUBLIC_KEY_FILE (default ~/.ssh/id_ed25519.pub) is the key the runner's root accepts; port
# 22 is open to this machine's current public address only, re-read at every create.

# Backticks in the --query strings are JMESPath literals, not command substitutions.
# shellcheck disable=SC2016
set -euo pipefail
shopt -s inherit_errexit

repo=$(realpath "$(dirname "$(realpath "$0")")/../..")
tf=$repo/scripts/cloud/aws
state=${XDG_STATE_HOME:-$HOME/.local/state}/cakeys/cloud/aws
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

out() { tofu output -raw "$1" 2>/dev/null || true; }

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
  local -a set=()
  while (($#)); do
    case $1 in
    --mode) set+=(--arg mode "${2-}") ;;
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
$p11/bin/configure-pkcs11 -a $hsm --disable-key-availability-check
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

probe() {
  tf_init
  local mode p11 opensc bin label name out rc=0
  mode=$(out mode)
  p11=$(pkg cloudhsm-pkcs11)
  name=${1:-cloudhsm-pkcs11/$(sed -E 's/.*-([0-9]+\.[0-9]+)\.[0-9]+$/\1/' <<<"$p11")+hsm2m-$(
    tr '[:upper:]_' '[:lower:]-' <<<"$mode"
  )}
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
  runner install -D -m 600 /dev/stdin /run/caprobe/pin <<<"caprobe:$(secret cu)"
  runner install -D -m 644 /dev/stdin /run/caprobe/keys.toml <<EOF
[tokens.cloudhsm]
module = "$p11/lib/libcloudhsm_pkcs11.so"
tokenLabel = "$label"
pinFile = "/run/caprobe/pin"
scratch = true
EOF
  # The checkout's profiles, as scripts/regen-profiles.sh passes them: --diff finds the committed
  # one even before the binary embeds it.
  runner rm -rf /run/caprobe/profiles
  tar -C "$repo" -c profiles | runner tar -C /run/caprobe -x
  local -a diff=()
  [[ -f $out ]] && diff=(--diff "$name")
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
destroy) destroy "$@" ;;
status) status "$@" ;;
*) usage ;;
esac
