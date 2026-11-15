#!/usr/bin/env bash
# Create and destroy the AWS CloudHSM test bed (docs/CLOUD_HSM.md, "AWS CloudHSM"): a VPC in
# us-west-1, a CloudHSM cluster with one HSM, and a NixOS runner in the cluster's security group.
# The infrastructure is scripts/cloud/aws/main.tf; this script runs OpenTofu on it.
#
#   scripts/cloud/aws.sh create [--mode FIPS|NON_FIPS] [--hsm-type T] [--instance-type T] [--nixos R]
#   scripts/cloud/aws.sh destroy [--park] [--yes]
#   scripts/cloud/aws.sh status
#
# create    brings everything up and prints the runner's address and the HSM's IP. The cluster is
#           left as AWS made it (UNINITIALIZED on first create); initializing and activating it
#           is a separate step. The flags are remembered: a later create needs none.
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

init() {
  tofu init -input=false -backend-config="path=$state/terraform.tfstate" >/dev/null
}

out() { tofu output -raw "$1" 2>/dev/null || true; }

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
  init
  apply_guarded "$next" -var park=false
  local cid
  cid=$(out cluster_id) ip=$(out runner_ip)
  cat <<EOF

cluster   $cid ($(out mode), $(cluster_state "$cid"))
hsm       $(out hsm_ip)
runner    root@$ip ($(out runner_ami))
          ssh -o StrictHostKeyChecking=accept-new root@$ip
billing   the HSM at \$1.81/h until '$0 destroy [--park]'
EOF
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
  init
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
destroy) destroy "$@" ;;
status) status "$@" ;;
*) usage ;;
esac
