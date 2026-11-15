# What scripts/cloud/aws.sh and gcp.sh drive the cloud test beds with (docs/CLOUD_HSM.md):
# OpenTofu with the AWS and Google providers from this nixpkgs, so `tofu init` fetches nothing
# from a registry, and the AWS CLI, gcloud and OpenSSL for the steps OpenTofu does not model.
{
  symlinkJoin,
  opentofu,
  awscli2,
  google-cloud-sdk,
  jq,
  curl,
  openssl,
}:
symlinkJoin {
  name = "cloud-tools";
  paths = [
    (opentofu.withPlugins (p: [
      p.hashicorp_aws
      p.hashicorp_google
    ]))
    awscli2
    google-cloud-sdk
    jq
    curl
    openssl
  ];
}
