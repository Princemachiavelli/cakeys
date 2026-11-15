# An AWS CloudHSM cluster with one HSM, and a NixOS runner in the same VPC that can reach it
# (docs/CLOUD_HSM.md, "AWS CloudHSM"). Driven by scripts/cloud/aws.sh, never by hand: the
# script keeps the state outside the repository and refuses any plan that would replace the
# cluster.
#
# Billed while it exists: the HSM ($1.81/h, hsm2m.medium in us-west-1) and the runner. With
# `park = true` both are deleted and the cluster, its last backup and the network stay; none of
# those bill by the hour. The next apply with `park = false` creates an HSM in the same cluster,
# which restores that backup.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
  # The path is set by `tofu init -backend-config=path=...` (scripts/cloud/aws.sh).
  backend "local" {}
}

variable "region" {
  type    = string
  default = "us-west-1"
}

variable "park" {
  description = "Delete the HSM and the runner, keep the cluster and the network."
  type        = bool
  default     = false
}

variable "mode" {
  description = "FIPS or NON_FIPS. Fixed for the cluster's life: changing it replaces the cluster."
  type        = string
  default     = "FIPS"
  validation {
    condition     = contains(["FIPS", "NON_FIPS"], var.mode)
    error_message = "mode is FIPS or NON_FIPS."
  }
}

variable "hsm_type" {
  type    = string
  default = "hsm2m.medium"
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "nixos_release" {
  description = "Picks the newest official NixOS AMI named nixos/<release>*-x86_64-linux."
  type        = string
  default     = "26.05"
}

variable "ssh_public_key" {
  type = string
}

variable "ssh_cidr" {
  description = "Who may reach the runner's port 22: the operator's address, as a /32."
  type        = string
}

variable "expires" {
  description = "UTC time after which the billed resources are leftovers (docs/CLOUD_HSM.md, Safety)."
  type        = string
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      caprobe = "1"
      project = "cakeys"
    }
  }
}

locals {
  name    = "caprobe"
  running = var.park ? 0 : 1
  # us-west-1 offers two zones, and their names differ per account.
  azs = slice(sort(data.aws_availability_zones.available.names), 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Network: the runner in a public subnet (SSH in, Nix substituters out), the HSM ENIs in
# private subnets with no route out, one per zone as create-cluster expects.

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = local.name }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.0.0/24"
  availability_zone       = local.azs[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${local.name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "hsm" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = "10.42.${count.index + 1}.0/24"
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.name}-hsm-${count.index}" }
}

resource "aws_security_group" "ssh" {
  name   = "${local.name}-ssh"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${local.name}-ssh" }
}

# The cluster. create-cluster makes its own security group, which admits its members on
# 2223-2225; the runner joins it.

resource "aws_cloudhsm_v2_cluster" "this" {
  hsm_type   = var.hsm_type
  mode       = var.mode
  subnet_ids = aws_subnet.hsm[*].id
  tags       = { Name = local.name }
}

resource "aws_cloudhsm_v2_hsm" "this" {
  count      = local.running
  cluster_id = aws_cloudhsm_v2_cluster.this.cluster_id
  subnet_id  = aws_subnet.hsm[0].id
}

# The runner: the official NixOS AMI, root over SSH with the operator's key.

data "aws_ami" "nixos" {
  most_recent = true
  owners      = ["427812963091"]
  filter {
    name   = "name"
    values = ["nixos/${var.nixos_release}*-x86_64-linux"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_key_pair" "operator" {
  key_name   = local.name
  public_key = var.ssh_public_key
}

resource "aws_instance" "runner" {
  count         = local.running
  ami           = data.aws_ami.nixos.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.public.id
  key_name      = aws_key_pair.operator.key_name
  vpc_security_group_ids = [
    aws_security_group.ssh.id,
    aws_cloudhsm_v2_cluster.this.security_group_id,
  ]
  root_block_device {
    volume_type = "gp3"
    volume_size = 30
  }
  metadata_options {
    http_tokens = "required"
  }
  tags = { Name = "${local.name}-runner", expires = var.expires }
  # A newer AMI must not replace a running runner.
  lifecycle {
    ignore_changes = [ami]
  }
}

output "cluster_id" {
  value = aws_cloudhsm_v2_cluster.this.cluster_id
}

output "cluster_state" {
  value = aws_cloudhsm_v2_cluster.this.cluster_state
}

output "cluster_security_group_id" {
  value = aws_cloudhsm_v2_cluster.this.security_group_id
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "mode" {
  value = var.mode
}

output "hsm_ip" {
  value = one(aws_cloudhsm_v2_hsm.this[*].ip_address)
}

output "runner_ip" {
  value = one(aws_instance.runner[*].public_ip)
}

output "runner_ami" {
  value = one(aws_instance.runner[*].ami)
}
