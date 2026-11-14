# Cloud HSM provider profiles (plan, 2026-11-13)

Goal: produce and re-verify capability profiles ([`PROVIDERS.md`](PROVIDERS.md)) for the managed
HSMs of the three big clouds that expose PKCS#11, by probing real instances provisioned on
demand and torn down afterwards. This file is research and plan; nothing here is built yet.

Naming: this tree is the `a11e92d` state of `main`, where the probe is still `cakeys probe`.
WORKPLAN D2 moves it to `caprobe`, "the only tool that creates and destroys scratch objects".
This plan is written against `caprobe`; read `cakeys probe` until stage 2 lands.

Evidence tags, extending PROVIDERS.md's: **[doc]** a vendor page read on 2026-11-13, not yet
reproduced here; **[api]** a vendor's public price API queried on 2026-11-13; **[inf]** my
inference from the above; **[todo]** unknown, and a named spike settles it. **[run]** is
reserved for what a probe or spike in this repo has shown. Nothing below is **[run]** yet. A
**[doc]** fact becomes **[run]** only when a probe confirms it, and the profile then replaces it.

## Verdict

| | Google Cloud KMS (Cloud HSM) | AWS CloudHSM | Azure Cloud HSM |
|---|---|---|---|
| PKCS#11 module | `libkmsp11.so` v1.9, Apache-2.0, prebuilt, no installer [doc] | Client SDK 5 `cloudhsm-pkcs11`, rpm/deb, licence not stated [doc] | Azure Cloud HSM SDK 2.0.2.5, deb/rpm/msi, MIT + BSD-3 + GPL-2.0 (driver) [doc] |
| OpenSSL engine | none in the repo; via libp11 on top of PKCS#11 [doc] | dynamic engine and OpenSSL 3 provider (`configure-dyn`, `configure-openssl-provider`) [doc] | OpenSSL listed among its interfaces [doc] |
| Reachable from | anywhere with a service account [doc] | private subnets of a VPC only [doc] | private endpoint in a VNet only [doc] |
| Needs a VM in the cloud | **no** | **yes** [inf] | **yes** [inf] |
| Parkable at $0 | yes: nothing runs | yes, if the HSM is deleted and restored from backup (mechanism below) [doc, todo] | **no**: bills until deleted; state parks as a backup blob |
| Billing while up | key versions: ~$1–2.5/month each [doc, third-party] | **$1.60/h per HSM**, us-east-1 hsm2m [api] | **$4.80/h per cluster of three HSMs**, eastus/westus2/centralus [api] |
| Fits camigrate as a target | **no** (no wrap/unwrap/create) [doc] | yes, with vendor wrap mechanisms [doc] | probably (AES-KW, RSA wrap) [doc] |
| Build order | 1st | 2nd | 3rd, gated on a budget decision |

**Name mapping.** "Azure Vault" is read as Azure Cloud HSM. Key Vault proper has no PKCS#11.
Azure Key Vault Managed HSM does ship a PKCS#11 library, but it is a TLS-offload library "for
F5 (BigIP) and Nginx only", mapping attributes to Key Vault tags [doc], so it cannot serve as a
conformance target. Azure Dedicated HSM (Thales Luna) is retired for new customers, supported
until 2028-07-31 [doc]. Neither is in scope.

**OpenSSL engines are informational.** The probe and `cakeys` speak PKCS#11 only; none of
SCOPE, ARCHITECTURE or DESIGN mentions an engine. The engine rows above record what exists, not
what we test.

**Not researched, candidates for later:** IBM Hyper Protect Crypto Services, Thales Luna Cloud
HSM, Entrust nShield as a Service, Fortanix DSM. Each ships a PKCS#11 client; each would reuse
the runner below.

## The constraint that decides everything

The vendor `.so` is loaded into `caprobe`'s own process, and only the Nix-built `caprobe`
carries the patched cryptoki the write probe needs (`scripts/regen-profiles.sh`). So the question
"how do we reach the HSM" is really "where does the Nix-built `caprobe` run, relative to the HSM's
network".

- **GCP:** the module makes gRPC calls to Cloud KMS [doc]. Run on this machine; no network
  placement exists.
- **AWS:** the HSM's ENIs sit in private subnets, and the cluster's security group admits only
  instances in that group [doc]. `caprobe` must run inside the VPC, or somewhere with a route into it.
- **Azure:** "accessible only from inside your virtual network" [doc]. Besides the module, the
  client needs the `azcloudhsm_client` daemon beside it, reaching the private endpoint on 443,
  444, 2224 and 2225 and resolving `*.privatelink.cloudhsm.azure.net` through a private DNS zone
  [doc].

### Options for AWS and Azure

| Option | Verdict |
|---|---|
| **Runner VM in the same VPC/VNet; `nix copy` the `caprobe` closure to it; run; copy the profile back.** | **Chosen.** No inbound path from the internet, and no long-lived credentials on the box: an instance profile (AWS) or managed identity (Azure) carries cloud API access. The runner is disposable and costs cents per hour. |
| VPN from this machine into the VPC/VNet | Rejected. AWS Client VPN or Site-to-Site and an Azure VPN gateway add a billed resource of their own; Microsoft documents site-to-site and point-to-site VPN as the only outside route [doc]; home NAT adds a failure mode; the vendor daemons would run on this machine. It would keep the HSM's IPs, so any certificate binding would hold, but it costs more than a VM for the same result. |
| SSH/SSM port-forward to `127.0.0.1`, vendor config pointed at the tunnel | Not a design dependency. Whether the AWS or Azure client validates the HSM's certificate against its IP or hostname is **not stated anywhere I could read** [todo]. An optional one-hour spike on AWS only (§Phase 2) settles it: if validation does not bind to the address, a bastion plus `-L` is the cheapest runner. The runner VM still stands as the fallback. |

**One runner pattern for both:** stock Ubuntu LTS from the cloud's marketplace, cloud-init
installs Nix (multi-user), and `nix copy --to ssh-ng://runner <caprobe + vendor modules>`. No
custom image to build or keep current, and the vendor `.so` runs from its own Nix closure.
`caprobe` is never run against a vendor `.so` installed through the distro: that would put two
glibc builds in one process.

The runner type needs no HSM. Sizing: one vCPU and 2 GB, spot or burstable where offered. The
sandbox hook, the lock and `cakeys` itself are not exercised on the runner; it runs `caprobe`
only.

## What each provider needs

### 1. Google Cloud KMS, protection level HSM

**Module.** Prebuilt linux-amd64 tarball from GitHub releases, signature checked with
`openssl dgst -sha384 -verify` [doc]; glibc 2.29 or later [doc]. Nix: `fetchurl` plus
`autoPatchelfHook`, pinned by hash, added to `pkgs.nix` as an unfree-marked derivation
(Apache-2.0 allows redistribution, but the hash pin keeps the repo free of blobs). Config is a
YAML file named by `KMS_PKCS11_CONFIG`, owner-writable only [doc]:

```yaml
tokens:
  - key_ring: "projects/<scratch-project>/locations/<loc>/keyRings/caprobe-<runid>"
    label: "kmtest"
refresh_interval_secs: 1   # keys made mid-run must appear [doc: default 0 = never]
```

**Credentials.** A service account, with a GCE-attached option [doc]. Whether the module honours
`GOOGLE_APPLICATION_CREDENTIALS` / ADC is **not stated** [todo, spike: first call with a key
file]. A dedicated project `caprobe-scratch`, one service account with
`cloudkms.admin`-level rights on that project only. `keys.toml`'s `pinFile` is ignored by the
module [doc: "Any supplied PIN is ignored"], so the token entry carries a dummy PIN file.

**Reach.** No VM. Run `caprobe` here.

**Isolation = key ring.** "Token = key ring" [doc]: a per-run key ring `caprobe-<runid>` is the
`scratch = true` token, so the scratch guard (refused with 17 otherwise) maps onto a boundary
the cloud itself enforces. Rings cost nothing and are unlimited [doc]; whether they can be
deleted is **disputed in the docs I read** ("you can delete key rings … in some circumstances"
versus the 2023 FAQ) [todo]. Plan on permanent empty rings.

**Lifecycle.**
- Create: `C_GenerateKey` / `C_GenerateKeyPair` create a CryptoKey with one version [doc].
- Destroy: `C_DestroyObject` schedules destruction (default 30 days) [doc]. The write probe's
  "delete really deletes" check therefore cannot be an absence check; the profile records
  "destroy = scheduled" and the probe must look for `DESTROY_SCHEDULED`, not absence [inf].
  The per-key `destroy_scheduled_duration` is set at creation; its minimum is **not stated**
  [todo]; I recall 24 hours, unverified. Destroyed versions are not billed [doc].
- Labels are CryptoKey IDs and cannot be reused after destruction [inf]; the probe must put the
  run ID in every label.

**Quotas that shape the probe.** Hardware-key write budget is 100 per minute; an asymmetric
HSM key create costs 50,000 of 3,000,000 HSM tokens per minute, so about 60 creates a minute;
reads are 600 per minute and the module reads the whole ring at every `C_Initialize` [doc,
quotas page, in effect since 2026-02-16]. The probe needs a throttle and a back-off on
`RESOURCE_EXHAUSTED` (HTTP 429), and must not re-initialise per check. Write-probe keys per run
should be counted before the run (§Safety).

**What the profile will say, expected.** Expect these gaps; the probe must record each as
`CKR_FUNCTION_NOT_SUPPORTED` or `CKR_MECHANISM_INVALID` cleanly, not as errors [doc]:
- No `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`, `C_CreateObject`, `C_SetAttributeValue`,
  digest functions, `C_InitToken`, `C_InitPIN`, `C_SetPIN`. So `camigrate` cannot import into or
  wrap out of it: no migration role.
- EC: P-256 and P-384 only. RSA 2048/3072/4096 with fixed digests (SHA-256, SHA-512 on 4096).
  AES-128/256 in GCM, CTR, CBC. HMAC SHA-1…512.
- `C_Login` accepts `CKU_USER` only and ignores the PIN; the SO role does not exist.
- `CKA_ID` is the full CryptoKeyVersion resource name; `CKA_LABEL` is the CryptoKey ID.

**Profile name and match fields.** `libkmsp11/1.9+hsm`. Protection level is D12-style state:
`HSM`, `HSM_SINGLE_TENANT` (new in 1.9) and `SOFTWARE` (only with `allow_software_keys`) are
three profiles by name, since PKCS#11 will not report it [inf]. Single-tenant is billed
separately and is out of scope for the first pass.

**Cost per run.** About $0.03–0.08 per key per day, if versions are pro-rated and live one day
[inf; the $1.00–2.50/month per-version price is a third-party figure, pro-rating unconfirmed]:
a 15-key probe is $0.50–2. (An earlier draft said "cents"; that was wrong.) The risk is the
destroy delay: the default is 30 days, and the docs say only that *destroyed* versions are not
billed, not whether versions *scheduled* for destruction are [todo]. If they are, a daily run of
~50 keys settles at ~1,500 live versions, $1,500–3,750 a month. Two things must be settled
before any daily automation: whether `libkmsp11` lets a created key carry a short
`destroy_scheduled_duration` (it creates the CryptoKey itself; not stated) and the key budget
per run. Until then, run by hand and read the bill.

### 2. AWS CloudHSM

**Module.** `cloudhsm-pkcs11` from the vendor's rpm/deb [doc] (Ubuntu 22.04/24.04/26.04, RHEL
8–10, Amazon Linux 2/2023, x86_64 and ARM64 [doc]); files under `/opt/cloudhsm`; PKCS#11 2.40
[doc]. Nix: `fetchurl` of the vendor package, `dpkg -x`, `autoPatchelfHook`, unfree. No
redistribution licence is stated [doc], so the repo carries the URL and the hash, never the
file. Config is the tool's JSON written by `configure-pkcs11 -a <eni-ip> --hsm-ca-cert <file>`
[doc]; the installer's paths under `/opt/cloudhsm` are rewritten in the derivation, or the
config is passed explicitly [todo].

**Credentials.** `cloudhsm-cli` creates the Crypto User; the PIN is `user:password` [doc]. The
password is the only long-lived secret: it lives in the operator's secret store, goes to the
runner over the SSH connection into a tmpfs file, and is passed to `caprobe` as `pinFile`. Never
in the repo, the Nix store or a log.

**Reach.** A runner in the cluster's VPC, in a subnet the cluster's security group admits
[doc]. The module's `-a <ip>` bootstrap needs only network reach; `--cluster-id` instead calls
`DescribeClusters`, which needs the AWS API or a VPC endpoint [doc], so the plan uses `-a`
with the IP from `describe-clusters` (the runner script reads it each run: whether a
re-created HSM keeps its IP is not stated [todo]).

**Lifecycle, "parked" design.** Done once, by hand, with a script:
1. `create-cluster --hsm-type hsm2m.medium --mode FIPS|NON_FIPS --backup-retention-policy …`
2. Sign the cluster CSR with a self-made CA kept offline, `initialize-cluster` [doc].
3. `create-hsm`, activate and create the CU (cloudhsm-cli), then **delete the HSM**: this
   triggers a backup, and "AWS CloudHSM does not delete a cluster's last backup" [doc].

Each run: `create-hsm` in the same cluster; the docs say "create a new one in the same cluster,
and this action will restore the backup you previously created with the delete HSM operation"
[doc]. Run, then `delete-hsm` to take the backup again. The cluster with no HSM in it carries no
HSM-hour charge [doc, third-party]. **[todo, spike]:** the page also says a first `create-hsm`
needs an *uninitialized* cluster, and does not say a zero-HSM, once-initialized cluster qualifies
or keeps its activation. Two fallbacks, in order of preference:
1. `create-cluster --source-backup-id` [doc: "will contain the same users, key material,
   certificates, configuration, and policies"], then `create-hsm`. Documented, explicit, a
   cluster per run.
2. Initialize and activate from scratch every run. Longest; no state to guard; the scripted
   CSR signing is a few openssl calls.

**One HSM.** The client must run with `disable_key_availability_check` set, because key
availability defaults to requiring keys on two HSMs [doc]. The profile records this; it is a
property of how we probe, not of the module.

**Mode is a profile axis.** FIPS and NON_FIPS are separate clusters and a backup restores only
into its own mode [doc]. D12 applies: they are separate observed profiles. Ed25519 exists on
non-FIPS only; `CKM_RSA_PKCS` for encrypt/wrap is deprecated in FIPS mode [doc]. Start with
**FIPS**, the mode a real deployment will use. A **NON_FIPS** cluster is a second pass.

**What the profile will say, expected [doc].**
- Key types: AES 128/192/256, 3DES, EC secp224r1/256r1/256k1/384r1/521r1, Ed25519
  (non-FIPS), ML-DSA 44/65/87 through vendor mechanism `CKM_CLOUDHSM_ML_DSA_KEY_PAIR_GEN`,
  RSA 2048–4096.
- OAEP with SHA-1, 224, 256, 384, 512 (unlike SoftHSM, SHA-1 only [run]).
- Wrap/unwrap: `CKM_RSA_PKCS_OAEP`, `CKM_AES_GCM`, `CKM_RSA_AES_KEY_WRAP` and vendor
  `CKM_CLOUDHSM_AES_KEY_WRAP_*`; the standard `CKM_AES_KEY_WRAP` is *listed in the summary and
  absent from the detail* [doc], a probe target.
- No `C_InitToken`; no SO role; sign/verify-recover unsupported.
- Whether `CKA_EXTRACTABLE`/`CKA_SENSITIVE` follow the usual rules is **not stated** [todo]; it
  decides camigrate's role.
- Vendor mechanism IDs are outside the OASIS baseline. The probe must record them by number and
  name them in the profile's `[manual]` section.

**Profile name.** `cloudhsm-pkcs11/<sdk-version>+hsm2m-fips`; the SDK version is what the module
reports [todo: check what `C_GetInfo` says, since D9 matches on it].

**Cost.** $1.60/h per hsm2m HSM [api]. A two-hour session is about $3.20, plus the runner.
Left running it is $1,168 per month. Backup storage price is **not stated** [todo].

### 3. Azure Cloud HSM

**Module.** SDK 2.0.2.5: PKCS#11 2.40, OpenSSL, JCE, KSP/CNG [doc]. Linux packages: Ubuntu
20.04/22.04/24.04 (deb; 22.04 and 24.04 use the OpenSSL 3 package), RHEL 7/8/9, CBL Mariner 2
[doc]. Distribution is from the GitHub repo's releases; the repo LICENSE is MIT, with BSD-3-Clause
for the client tools and SDK and GPL-2.0 for the Marvell driver [doc]. Whether the driver is needed
on a network client is **not stated** [todo]. Nix: the same `fetchurl` + `autoPatchelfHook`
derivation as AWS, plus the daemon `azcloudhsm_client`, which the runner starts under a
transient systemd unit and which the vendor expects as a long-lived process [doc].

**Credentials.** The PIN is `user:password` (a CU), as in AWS [doc]. The partition-owner
certificate PO.crt "is uploaded during HSM initialization" and cannot be changed; PO.key is
needed only for initial signing and CO resets [doc]. Keep PO.key with the operator, never on the
runner; the runner needs PO.crt only.

**Reach.** Private endpoint into a VNet, a private DNS zone `privatelink.cloudhsm.azure.net`
linked to it, and a runner in that VNet [doc]. Cluster = three HSMs behind one endpoint [doc].

**Lifecycle.** Azure Cloud HSM **bills hourly and cannot be paused; only deletion ends charges**
[doc]. So the parking design differs from AWS: park as a **backup blob**, not as an idle
resource. Backup needs a user-assigned managed identity and a storage account with Storage Blob
Data Contributor, and restore goes to a *non-activated* cluster in any region (not the source,
not an activated one) [doc]. Per run: create cluster → restore the backup (replaces activation)
→ run → back up if the run changed state → delete. **[todo, spike]:** how long create takes
(the docs never say), whether a restored cluster keeps its CU users and PO.crt, and whether the
three-node minimum applies to a restore. If restore does not remove activation, activation
itself is manual, uses SDK tools and an onboarding guide shipped as a PDF [doc]: a scripted
activation is its own piece of work.

**Cost.** $4.80 an hour per cluster in eastus, westus2 and centralus (Standard_B1) [api]. That is
$115/day and about $3,500/month if left up. A session of 2–3 hours, create time included,
is about $10–15 [inf]. The decision belongs to the user (Phase 3).

**What the profile will say, expected [doc].** RSA 2048/3072/4096 with encrypt, decrypt, wrap,
unwrap, sign, verify; EC P-256, P-256K, P-384, P-521 and Ed25519, sign/verify only; AES
128/192/256 with AES-CBC, AES-GCM and AES-KW. A hard cap of 3,200 key handles; create-key
throughput is 1 per second [doc]. The mechanism names are **not stated** [todo]; the probe is
the source.

## Profile integration

- Names follow the repo's `module/version+hardware` rule (D10): `libkmsp11/1.9+hsm`,
  `cloudhsm-pkcs11/<ver>+hsm2m-fips`, `azure-cloud-hsm/2.0.2.5`. A cloud service is a "hardware"
  the repo cannot see beneath, so profiles are pairs and `profiles/hardware/` stays empty for it.
- FIPS mode and protection level are D12 axes: `[match.fields]` where PKCS#11 3.2 reports them
  (`CKO_VALIDATION`, `CKF_ERROR_STATE`, `C_GetSessionValidationFlags`), by name where it does not.
- A cloud token's `keys.toml` entry sets `scratch = true`, `pinFile` pointing at a runtime file,
  and a `module` path from the Nix store. Credentials are file paths read at run time, never
  committed (the same rule as the YubiKey's, WORKPLAN "Hardware rules").
- The committed profile TOML is embedded like the others (`crates/profile/src/embedded.rs`).

### Conformance and the Nix build

PROVIDERS.md says the conformance test re-probes on every build. A cloud profile cannot: the
sandbox has no network, and a probe costs money. The repo already has the escape: the hardware
tests are opt-in, skipped when their module variable is unset, "never in the Nix build"
(`crates/cli/tests/ftpm.rs`, `yubikey.rs`). Cloud follows it:

- `crates/cli/tests/cloud.rs`, gated on `CAKEYS_CLOUD_<PROVIDER>_MODULE`, probes and diffs
  against the committed profile, exactly as `yubikey.rs` does at the end of its suite.
- A pure check in the build: the profile parses, and its match keys resolve, as for any
  profile.
- `scripts/regen-cloud-profiles.sh`, separate from `regen-profiles.sh` so a regeneration of
  softhsm/kryoptic/tpm2 never bills a cloud. It drives the runner, writes
  `profiles/modules/<module>/<ver>+<hw>.toml` over its committed file, and keeps `[migration]`
  and `[manual]`, as the existing script does.

## Orchestration

Two layers, because their lifetimes differ.

- **Base layer, applied once, kept:** networking (VPC/VNet, private subnets, security group,
  DNS zone and private endpoint where required), the KMS project and service account, the
  runner's identity, the Azure backup storage account, and a **budget with an alert**. OpenTofu
  (`nix shell nixpkgs#opentofu`), one directory per provider, state kept local and out of git.
  None of it bills at idle except the Azure private endpoint (cents per hour) [inf].
- **Run layer, per session:** HSM and runner. Plain bash around the vendor CLIs
  (`nixpkgs#awscli2`, `#azure-cli`, `#google-cloud-sdk`), because the sequence includes steps
  Terraform models poorly: CSR signing, activation, waiting on cluster states, restoring from
  backup. One entry point per provider with the same three verbs:
  `scripts/cloud/<provider> up | probe | down`, and `scripts/cloud/status`.

`probe` runs `caprobe probe --token <t> --write --diff <profile> --out <file>` on the runner
(or here, for GCP) and copies the generated TOML back.

### Safety against a leaked bill

- `down` runs from a `trap` on EXIT, INT and TERM in `up`/`probe`; it deletes the HSM and the
  runner and is idempotent.
- Every run-layer resource carries `caprobe=1` and `expires=<UTC ISO>` (now + 4 h). `status`
  lists everything with the tag, across all three providers, with its hourly rate, and prints a
  non-zero exit when any exists. `reap` deletes what is past `expires`.
- The budget alert is set at a figure the user picks (Phase 0). On AWS CloudHSM and Azure Cloud
  HSM billing lags by hours, so the alert is a backstop, not a control; `status` is the control.
- The Azure rate is the one that hurts: $115/day. Phase 3 does not start without a ceiling.

## Phases

| Phase | Work | Exit | Spend |
|---|---|---|---|
| 0 | Decisions: runner pattern, budgets, accounts/projects (below) | answers recorded | $0 |
| 1 | **GCP.** `libkmsp11` derivation. `caprobe probe` read-only against a scratch ring, then `--write`. Throttle and back-off. `libkmsp11/1.9+hsm.toml`, the gated test, the regen script | probe is byte-stable twice in a row; destroy semantics and billing while scheduled recorded | $0.5–2 per run, unless scheduled versions bill for 30 days (spike 3) |
| 2 | **AWS.** Runner and base layer. `cloudhsm-pkcs11` derivation. Bootstrap once. Spike: zero-HSM restore, then (optional, 1 h) tunnel to `127.0.0.1`. `up`/`probe`/`down`. FIPS profile | parked cycle works twice; `status` is empty after `down`; profile committed | ~$10 |
| 3 | **Azure.** Gate: user sets a ceiling. Reuse the runner module. Spikes: create time, restore-replaces-activation, driver need. Profile | as Phase 2 | ~$15 per attempt |
| 4 | **Close-out.** Move the conclusions into PROVIDERS.md; record the cloud tokens in CONFIG.md; add what each cloud needs to WORKPLAN's hardware rules (the cloud credentials, the ceiling) | docs consistent | $0 |

Dependencies: phases 1–3 need the Nix-built `caprobe`, so they come after WORKPLAN stage 2 (the
split from `cakeys`) and should be built on that branch. In this tree's current state they would
be written against `cakeys probe` and renamed later.

### Spikes, in one list

Each turns a **[todo]** into **[run]**. Their order is by cost.
1. libkmsp11 auth route: ADC vs key file (GCP, free).
2. Write quota behaviour under the probe's real load (GCP, cents).
3. Destroy-scheduled minimum, whether libkmsp11 can set it on a key it creates, key-ring
   deletion, per-version billing while scheduled and its pro-rating granularity (GCP). This one
   gates daily runs: see the GCP "Cost per run".
4. AWS zero-HSM `create-hsm` restore: does the cluster stay initialized and activated; does
   the HSM IP change; time for create and delete.
5. AWS tunnel: does the client accept `-a 127.0.0.1`.
6. AWS: `CKA_EXTRACTABLE`/wrap behaviour, standard AES-KW; what `C_GetInfo` reports.
7. Azure: create time, restore semantics, driver need, mechanism names, what `C_GetInfo` reports.

## Open questions for the user

1. Do accounts exist for all three (a GCP project, an AWS account, an Azure subscription), and
   is a $20–50 monthly ceiling right for AWS+GCP, with Azure separate?
2. Azure at $4.80/h per cluster of three: do it, or stop at AWS and GCP? The Azure profile
   is the only one that needs an expensive resource and the manual activation path.
3. AWS: FIPS first, NON_FIPS later (assumed above)?
4. Build base: these phases need the `caprobe` split (WORKPLAN stage 2, committed) and the
   stage-3 working tree. The worktree here is `main` at `a11e92d` with neither. Branch the work
   from `stage3-2026-11-13` once it is committed, or do the research doc here and rebase?

## Sources

- AWS: [PKCS#11 library](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html),
  [install](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html),
  [mechanisms](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html),
  [key types](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html),
  [connect the client](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cluster-connect.html),
  [configure parameters](https://docs.aws.amazon.com/cloudhsm/latest/userguide/configure-tool-params5.html),
  [initialize a cluster](https://docs.aws.amazon.com/cloudhsm/latest/userguide/initialize-cluster.html),
  [backups](https://docs.aws.amazon.com/cloudhsm/latest/userguide/backups-using.html),
  [backup retention](https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-backup-retention.html),
  [create from backup](https://docs.aws.amazon.com/cloudhsm/latest/userguide/create-cluster-from-backup.html),
  [create HSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/create-hsm.html),
  [price list (us-east-1)](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/CloudHSM/current/us-east-1/index.json).
- Google: [kmsp11 user guide](https://raw.githubusercontent.com/GoogleCloudPlatform/kms-integrations/refs/heads/master/kmsp11/docs/user_guide.md),
  [releases](https://github.com/GoogleCloudPlatform/kms-integrations/releases),
  [PKCS#11 FAQ](https://github.com/GoogleCloudPlatform/kms-integrations/wiki/PKCS%2311-FAQs),
  [library reference](https://docs.cloud.google.com/kms/docs/reference/pkcs11-library),
  [destroy and restore](https://docs.cloud.google.com/kms/docs/destroy-restore),
  [quotas](https://docs.cloud.google.com/kms/quotas.md.txt).
- Azure: [overview](https://learn.microsoft.com/en-us/azure/cloud-hsm/overview),
  [FAQ](https://learn.microsoft.com/en-us/azure/cloud-hsm/faq),
  [network security](https://learn.microsoft.com/en-us/azure/cloud-hsm/network-security),
  [quickstart](https://learn.microsoft.com/en-us/azure/cloud-hsm/quickstart-powershell),
  [backup and restore](https://learn.microsoft.com/en-us/azure/cloud-hsm/backup-restore),
  [service limits](https://learn.microsoft.com/en-us/azure/cloud-hsm/service-limits),
  [SDK repo](https://github.com/microsoft/MicrosoftAzureCloudHSM),
  [Managed HSM TLS offload](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/tls-offload-library),
  [Dedicated HSM retirement](https://learn.microsoft.com/en-us/azure/dedicated-hsm/overview),
  [Retail Prices API](https://prices.azure.com/api/retail/prices).
- Third-party, unconfirmed against the vendors' own pages: GCP per-version HSM price
  ([FitGap](https://us.fitgap.com/products/google-cloud-hsm),
  [NicheeLab](https://nicheelab.com/en/articles/gcp/cloud-kms-hsm-guide/)).
