# What scripts/cloud/aws.sh drives the AWS CloudHSM runner with (docs/CLOUD_HSM.md): OpenTofu
# with the AWS provider from this nixpkgs, so `tofu init` fetches nothing from a registry, and
# the AWS CLI and OpenSSL for the steps OpenTofu does not model.
{
  symlinkJoin,
  opentofu,
  awscli2,
  jq,
  curl,
  openssl,
}:
symlinkJoin {
  name = "cloud-tools";
  paths = [
    (opentofu.withPlugins (p: [ p.hashicorp_aws ]))
    awscli2
    jq
    curl
    openssl
  ];
}
