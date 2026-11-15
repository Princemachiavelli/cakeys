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
  # The probe's rows only: the table also holds every algorithm cakeys may ask for.
  keys = {
    for k in jsondecode(file("${path.module}/../../../crates/kmsp11/src/keys.json")) :
    "caprobe-${replace(lower(k.algorithm), "_", "-")}" => k if k.probe
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
  for_each                      = local.keys
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
  value = sort(keys(local.keys))
}
