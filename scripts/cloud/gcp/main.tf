# The Cloud KMS test bed for libkmsp11 (docs/CLOUD_HSM.md, "Google Cloud KMS"), driven by
# scripts/cloud/gcp.sh: the Cloud KMS API, one key ring, and one CryptoKey per algorithm of the
# kmsp11 provider's table (crates/kmsp11/src/keys.json, the probe's own), each with no version
# and the shortest destroy-scheduled duration. The probe adds a version to each and destroys it;
# the version then spends 24 hours scheduled for destruction, not Cloud KMS's default 30 days,
# which a key libkmsp11 created itself would get. The duration is fixed when a key is created.
#
# Nothing here bills while no version exists: keys and rings are free. Rings and keys cannot be
# deleted while they hold versions not yet destroyed, so neither is ever destroyed from here.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google" }
  }
  # The path is set by `tofu init -backend-config=path=...` (scripts/cloud/gcp.sh).
  backend "local" {}
}

variable "project" {
  type = string
}

variable "location" {
  description = "A Cloud KMS location that offers protection level HSM."
  type        = string
  default     = "us-west1"
}

provider "google" {
  project = var.project
  # User credentials bill API quota to this project, not to gcloud's own.
  billing_project       = var.project
  user_project_override = true
}

locals {
  table = jsondecode(file("${path.module}/../../../crates/kmsp11/src/keys.json"))
  # The probe's rows only: the table also holds every algorithm cakeys may ask for.
  keys = {
    for k in local.table :
    "caprobe-${replace(lower(k.algorithm), "_", "-")}" => k if k.probe
  }
  # The keys scripts/cloud/gcp/cakeys.toml realises, pre-created the same way so cakeys only adds
  # versions. Each algorithm must be the one the kmsp11 provider chooses for its spec, or
  # libkmsp11 refuses the version (CKR_ARGUMENTS_BAD): a free check of the mapping.
  cakeys_keys = {
    for label, algorithm in {
      "cakeys-ec-p256"          = "EC_SIGN_P256_SHA256"
      "cakeys-ec-p384"          = "EC_SIGN_P384_SHA384"
      "cakeys-rsa-sign-2048"    = "RSA_SIGN_PKCS1_2048_SHA256"
      "cakeys-rsa-decrypt-3072" = "RSA_DECRYPT_OAEP_3072_SHA256"
      "cakeys-hmac-sha256"      = "HMAC_SHA256"
    } : label => one([for k in local.table : k if k.algorithm == algorithm])
  }
}

# The Cloud KMS API is enabled by gcp.sh with gcloud: managing it from here needs the Cloud
# Resource Manager API, which a fresh project does not have either.
resource "google_kms_key_ring" "caprobe" {
  name     = "caprobe"
  location = var.location
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "probe" {
  for_each                      = merge(local.keys, local.cakeys_keys)
  name                          = each.key
  key_ring                      = google_kms_key_ring.caprobe.id
  purpose                       = each.value.purpose
  destroy_scheduled_duration    = "86400s"
  skip_initial_version_creation = true
  version_template {
    algorithm        = each.value.algorithm
    protection_level = "HSM"
  }
  labels = { caprobe = "1" }
  lifecycle {
    prevent_destroy = true
  }
}

output "key_ring" {
  value = google_kms_key_ring.caprobe.id
}

output "keys" {
  value = sort(keys(merge(local.keys, local.cakeys_keys)))
}
