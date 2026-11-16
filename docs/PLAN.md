# Plan: PKCS#11 spec coverage review and boot-chain integration tests

Two pieces of work, planned 2026-11-14. Built: A1 (2026-11-15) and A3 (p11-fault).

- **Part A** reviews how much of PKCS#11 3.2 cakeys implements, handles or deliberately
  refuses, and turns the answer into data and tests.
- **Part B** adds integration tests in which a cakeys-pinned token key is the root of trust for a
  boot chain: UEFI Secure Boot with a signed UKI, a swtpm whose Endorsement Key certificate the
  HSM issued, and an ARMv8 QEMU chain where TF-A hands an HSM-derived HUK to OP-TEE and Linux
  user space verifies it through the OP-TEE PKCS#11 TA and the fTPM.

Evidence tags, as in [CAPROBE.md](CAPROBE.md): **[run]** verified in this repo, **[src]** read
in a source tree, **[spec]** from a standard, **[todo]** not verified yet. Sources read for this
plan: the flake's nixpkgs (26.11pre, 2026-11-08), OP-TEE 4.7.0 and TF-A 2.14.0 as nixpkgs
fetches them.

Everything in Part B runs on QEMU, swtpm and software tokens. None of it touches the
development machine's AMD fTPM or the YubiKey ([DEVELOPMENT.md](DEVELOPMENT.md), "Hardware
rules"). "fTPM" below always means the OP-TEE firmware-TPM TA inside the QEMU guest.

## Summary

| Stage | What | Size | Depends on |
|---|---|---|---|
| S | Five spikes that settle the [todo] items the later stages rest on | 5 × S | — |
| A1 | Coverage as data: baseline gains return values and flags; a traced coverage file | M | — |
| A2 | Section-by-section semantic review; findings filed in OPEN.md | M | A1 |
| A3 | A forwarding shim that misbehaves on request: deterministic bad-module tests | S–M | — |
| A4 | The object matrix (OPEN.md, "Identity coverage") | L | A1 |
| A5 | KDF probes in caprobe; a derive-based commitment for derive-only secret keys | M | A1 |
| A6 | Cross-tests: pkcs11-proxy-ng (and pkcs11-proxy) as forwarder layers; one pkcs11-check run | M | — |
| B1 | x86 Secure Boot: PK/KEK/db in a token, UKI signed in a sandboxed Nix build | M | S1 |
| B2 | swtpm manufactured by the HSM: EK certificate, AK chained to it, quote of B1 | M–L | S2, B1 |
| B3 | OP-TEE PKCS#11 TA as a reference token, aarch64 QEMU | M | S3 |
| B4 | TF-A to OP-TEE HUK handoff, verified from user space | L | S4, B3 |
| B5 | fTPM on the injected HUK; tpm2-pkcs11 on it; EK certificate from the HSM | L | S5, B4, B2 |
| B6 | Trusted Board Boot: ROTPK from the lock, FIP signed through PKCS#11 | M | B3 |

S is a day or less, M two to four days, L one to two weeks. A and B are independent; inside B
the x86 line (B1, B2) and the ARM line (B3–B6) are independent until B5 reuses B2's verifier.

## Part A: PKCS#11 coverage review

### A0. Where cakeys stands (static count, 2026-11-14)

The denominator is the generated baseline, `profiles/baselines/pkcs11-3.2.toml` [run]. The
numerator below is a grep of `crates/*/src`, so it is a lower bound to be replaced by A1's trace.

| Vocabulary | Baseline | cakeys touches | Notes |
|---|---|---|---|
| Functions | 104 | about 30 | session, find, get-attribute, create, destroy, generate, sign, encrypt, decrypt, wrap, unwrap, derive |
| Object classes | 12 | 5 | no `CKO_PROFILE` (D4), `CKO_VALIDATION` (D12), `CKO_TRUST`, `CKO_DOMAIN_PARAMETERS`, `CKO_HW_FEATURE`, `CKO_MECHANISM`, `CKO_OTP_KEY` |
| Key types | 68 | 10 | RSA, EC, Edwards, AES, generic secret, five HMAC types |
| Mechanisms | 472 | about 38 | identity, proof of possession, generation, migration wraps |
| Attributes | 154 | about 45 | read or set directly, plus the policy table in `core::attrs` |
| Parameter sets | 26 | 0 | all post-quantum or PBKDF2 |
| Return values, flags, user types | not in the baseline | 12 `RvError` variants matched by name | the gap A1 closes first |

Low percentages are expected: cakeys pins and verifies keys, it is not a general PKCS#11
consumer. The review's job is to make every unused row a decision (out of scope, with a reason)
or a finding, instead of an accident.

### A0b. Related projects (reviewed 2026-11-14)

Checkouts in `~/srcs`. None does what cakeys does; what each is to us:

| Project | What it is | To us |
|---|---|---|
| [pkcs11-check](https://github.com/mingulov/pkcs11-check) | Python/pytest conformance and robustness suite over a ctypes binding: >100k checks (spec, strict `CK_RV`, Wycheproof, ACVP, fuzz), crash isolation, findings as evidence | A second opinion on the reference modules (one run, findings triaged, never a check), and references for A1 (its per-call `CK_RV` trace, `docs/rv-trace-design.md`) and A2 (the OASIS 3.2 profile tables, `compliance_profiles.py`). Not caprobe: it reports, caprobe decides. Its roadmap asks for what a caprobe profile is (which curves, sizes and mechanisms a module implements, to scope a run) |
| [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) | Rust PKCS#11 remote proxy: a `cdylib` shim exporting the C ABI, gRPC/mTLS, a daemon over `cryptoki-sys`. v0.3.1 beta, six months old, one maintainer; "not production-ready" by its own matrix; one trusted client per daemon | A forwarder to cross-test (A6). Its shim shows how to export the PKCS#11 C ABI from Rust (A3). Its fault injection is an in-process mock of its own backend, not a module cakeys could load |
| [pkcs11-proxy](https://github.com/iksaif/pkcs11-proxy) | C, gnome-keyring's `gck-rpc` (p11-kit's RPC ancestor) over plain TCP; a mechanism whitelist without hashed ECDSA, EdDSA, ECDH, `AES_CMAC`, any AES key wrap | Optional A6 case: a very restrictive forwarder |
| [pkcs11-components](https://github.com/mingulov/pkcs11-components) | `pkcs11-module` (raw `C_GetFunctionList`/`C_GetInterfaceList` acquisition), `pkcs11-abi` (function-table layouts, 3.x prefix selection), `pkcs11-types` | Only if A3's shim ever needs 3.x interfaces; cryptoki covers cakeys itself |
| [haskoki](https://github.com/mingulov/haskoki) | Haskell software token over OpenSSL 4: a demonstrator (keys unencrypted at rest), two months old, 316 mechanisms tested in its own model, PQC | Implements everything cakeys uses plus PQC. Parked (OPEN.md): another OpenSSL-backed software token adds little beside kryoptic until cakeys has PQ key types, and it is Docker-packaged, not in nixpkgs |
| [p11scope](https://github.com/mingulov/p11scope) | eBPF uprobe observer of the PKCS#11 calls running programs make | Not for the checks. A sandbox with `auto-allocate-uids` (as `test-nspawn`) runs as uid 0 in a user namespace, and capabilities there do not count for `bpf()`: tried 2026-11-14 on this host (kernel 7.2.9, `unprivileged_bpf_disabled = 2`), namespaced root gets no BPF program type at all, not even `socket_filter`. Only a BPF token (kernel 6.9+: a bpffs mounted with delegation by a privileged parent) would let it in, which the Nix daemon does not set up and p11scope would have to support. For A1, `pkcs11-spy` or A3's recorder |
| [pk11-uri-parser](https://crates.io/crates/pk11-uri-parser) | RFC 7512 URI parser crate | A2: parse every URI `uri.rs` emits in a test (the `/` escaping question) |
| [native-pkcs11](https://github.com/google/native-pkcs11) (reviewed 2026-11-15, 0.2.27) | Google's Rust PKCS#11 *module* over the macOS Keychain, for client certificates (SSH, browsers, VPN). The Windows backend is a stub (`todo!()`). Sign-only (raw and hashed RSA PKCS#1, PSS, raw `CKM_ECDSA`), one read-only slot: no create, generate or destroy, `C_Login` accepts any PIN. Not in nixpkgs; its conformance driver, google/pkcs11test, is neither, and pkcs11-check covers that role | Nothing to depend on or copy: p11-fault already exports the C ABI, and catches panics, which this module leaves to `panic = "abort"`. Its worth is as a real module that lies [src]: private-key policy is constants (`CKA_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` true, `CKA_EXTRACTABLE`, `CKA_LOCAL` false, `CKA_EC_PARAMS` P-256 for every key, RSA included), whatever the keychain holds; its searches are wrong both ways, since a label or ID lookup returns only the keychain's first match (`limit(1)`) and the key an ID lookup returns is a second, unlabelled object (objects compare by ID and label, in a store kept for the process), so the locator's 12 misses real duplicates, fires on a unique key once `check_unique_private_id` searches by ID after a label locator (with a `pinFile`), and a locator naming both label and ID finds nothing; and an attribute type it does not know ends `C_GetAttributeValue` without touching that entry, which cryptoki then reads as zero (OPEN.md, "Upstream"). Evidence for A2 and DESIGN §8.2, two rule kinds for A3 (FAULT_SHIM.md), and a `CKO_PROFILE` claim for D4. As a Darwin reference token: parked (OPEN.md) |

**Is testing p11-kit enough for forwarders?** For cakeys' design, yes; for behaviour, no.
p11-kit names itself in `C_GetInfo`, so cakeys applies its layer. pkcs11-proxy and
pkcs11-proxy-ng pass the backend's `C_GetInfo` through and are invisible: a token behind them
gets the backend's profile. Both purge what they cannot forward from `C_GetMechanismList`, so
mechanism-level decisions hold; what they change beyond the list (parameter marshalling,
pkcs11-proxy's OAEP parameters copied raw with their pointer, its 2026 `CK_ULONG` width fix) is
not seen. A6 covers that.

**Production use.** For forwarding today, p11-kit: mature, the distribution default, local or
over SSH through `p11-kit server`, at the price of the mechanisms its RPC drops.
pkcs11-proxy-ng forwards more (mechanism parameters, mTLS, audit) and backs its parity claim
with pkcs11-check, but is an early beta.

### A1. Coverage as data

1. **Extend the baseline generator** (`profile::baseline`, `Baseline::from_headers`) to emit
   `CKR_*`, `CKF_*`, `CKU_*`, `CKS_*`, `CKC_*`, `CKG_*`, `CKD_*` and `CKZ_*` from the vendored
   headers. Regenerate with `CAKEYS_UPDATE_BASELINE=1`; the pinned test keeps it honest.
2. **Trace what cakeys really calls.** Run the token suites under OpenSC's `pkcs11-spy.so`
   (in nixpkgs' `opensc`) in the check phase, and reduce the log to the set of
   (function, mechanism, attribute, return value) tuples seen per reference token. If the spy's
   log proves too lossy, the A3 shim records the same thing. [todo: spy output parses reliably]
3. **Commit the result** as `profiles/coverage/cakeys.toml`, generated and pinned byte for byte
   like the module profiles. Each baseline row gets one status:

   | Status | Meaning |
   |---|---|
   | `used` | traced in a test, with the tests that reach it |
   | `profile` | cakeys never calls it but a capability profile records it |
   | `refused` | cakeys meets it and refuses, with the exit code |
   | `out-of-scope` | a written reason (hand-kept section, preserved by the generator like `[manual]`) |
   | `gap` | should be handled and is not: an OPEN.md item |

4. **A check**: the build fails if a baseline row has no status, or a `used` row was not traced.
   A new spec revision or a new code path then shows up as a diff.
5. `caprobe supports` already answers "can this module do X"; add `caprobe coverage [<name>]`
   only if a consumer asks. The TOML is the interface.

Exit: every one of the baseline's rows has a status, and `docs/CAPROBE.md` gains a short
section on the file.

**Built** (2026-11-15). Step 2 traces with p11-fault rather than pkcs11-spy: tagged copies in
front of every module (`nix/test-tokens.sh`), a trace line per call with its mechanism
(parameters included), template, flags and calling program. The pass runs second, in the crane
check phase; the first stays direct. Statuses: 176 used, 79 gap, 831 out-of-scope, 11 profile.
The 3.x entry point (`C_GetInterface`) is the one thing the trace cannot see. See CAPROBE.md,
"Coverage", and `scripts/coverage-file.sh`.

### A2. Semantic review

Names being present says nothing about behaviour. Review each area against the spec text, one
short findings table per area in `docs/archive/REVIEW-<date>-pkcs11.md`, each finding ending as
a test, a profile row, a fix or an OPEN.md item. Questions already visible from reading the
code are listed so the review starts from them.

| Area | Questions |
|---|---|
| Library and slots | `C_Initialize` arguments and locking flags; the `C_Finalize` crash under parallel tests (OPEN.md, Engineering); `C_GetInterface` on 3.x modules against a module reporting 2.40 (tpm2-pkcs11); two tokens with one label; a token removed mid-run maps to 16 |
| Token flags | `CKF_PROTECTED_AUTHENTICATION_PATH` (a PIN pad: no `pinFile` to pass; native-pkcs11 sets it, with `CKF_LOGIN_REQUIRED` unset, and leaves authentication to the OS, A0b); `CKF_USER_PIN_TO_BE_CHANGED`; `CKF_TOKEN_INITIALIZED` unset; `CKF_LOGIN_REQUIRED` unset; `CKF_ERROR_STATE`. Only write protection and PIN counts are read today |
| Sessions and login | SO and user sessions together (`CKR_SESSION_READ_ONLY_EXISTS`); `C_LoginUser` (3.0); context-specific login for `pop-ecdh` and `pop-decrypt` (OPEN.md) |
| Storage attributes | `CKA_MODIFIABLE = true`: a verified key's policy can change after the check, so should it lower assurance or warn; `CKA_COPYABLE`; `CKA_DESTROYABLE = false` and `delete`; `CKA_UNIQUE_ID` (3.0) as evidence of a replaced object; `CKA_START_DATE`/`CKA_END_DATE` |
| Key attributes | `CKA_CHECK_VALUE`: the spec's own KCV, how it relates to `kcv-ecb`, and what it leaks; the template arrays (`CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE`), blocked on a cryptoki patch; `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` (3.2) |
| Certificates | Are `CKA_SUBJECT`, `CKA_ISSUER`, `CKA_SERIAL_NUMBER` checked against the DER in `CKA_VALUE`, or ignored; `CKA_CERTIFICATE_CATEGORY`; `CKA_TRUSTED`; `CKO_TRUST` (3.2) as the spec's own trust-anchor object, which Secure Boot keys make relevant |
| EC encodings | `CKA_EC_PARAMS` as named curve, explicit parameters or curve name string (all three are legal [spec]); compressed points; Edwards and Montgomery naming across 3.0 and 3.2; `CK_EDDSA_PARAMS` (ph, context) |
| Mechanism parameters | Each used mechanism's parameter struct against the spec: OAEP hash, MGF and source agreeing; PSS salt length; ECDH public data raw or DER; AES key wrap default IV; KWP against the historic `AES_KEY_WRAP_PAD` confusion |
| `C_GetMechanismInfo` | Flags and key-size bounds are read only for RSA today (OPEN.md, "More probes") |
| Return values | A table of every `CKR_*` each call can return [spec] against the exit code it maps to; anything reaching the default arm by accident is a finding |
| 3.0 to 3.2 additions | Triage each: message-based AEAD, `C_SessionCancel`, authenticated wrap, `C_VerifySignature`, async functions, KEM functions, stateful hash signatures (HSS, XMSS: relevant to firmware signing). ML-KEM private keys can only decapsulate, so post-quantum support needs a `pop-kem` binding |
| Conformance profiles | Which of the spec's consumer profiles cakeys needs from a module (Baseline, Extended, Authentication Token), stated once |
| RFC 7512 URIs | `uri.rs` leaves `/` unescaped; the RFC's `pk11-pchar` appears not to allow it [todo: check §2.3]. Non-UTF-8 labels; a label and serial that still match two tokens |

The URI row is also tested from outside: B1 and B2 hand cakeys' URI to OpenSSL
(`pkcs11-provider`), the libp11 engine, GnuTLS (swtpm) and p11-kit, so four independent parsers
check it.

Exit: the review document exists, each finding has an owner artefact, and OPEN.md is updated.

### A3. A lying module

DEVELOPMENT.md records that most bugs came from module behaviour and the design, not the pure
logic. Reference tokens only show the misbehaviour they happen to have. A module that
misbehaves on request makes that class testable on purpose; it is also tier 4 of
[COVERAGE_PLAN.md](COVERAGE_PLAN.md), where most of the remaining uncovered lines are.

**How it is built (decided 2026-11-14): a forwarding shim, not a module**, designed in
[FAULT_SHIM.md](FAULT_SHIM.md). `libp11_fault.so` (`crates/p11-fault`, about 1–1.5k lines,
no new dependencies) loads a real module (SoftHSM, kryoptic, a vendor's) named by
`P11_FAULT_MODULE` and forwards all 68 2.40 functions to it through generated forwarders,
changing only what the plan in `P11_FAULT_PLAN` says: a return value on the n-th call, an
attribute dropped, replaced or read from another object, a token flag set, a second object
under the locator, another key used than the one shown (the RSA proof that runs and fails,
which no reference can be led into), malformed lengths. `P11_FAULT_TRACE` records every call
(A1's trace if `pkcs11-spy` falls short). Nothing in it implements cryptography, objects or
sessions; the real module does.

Being a module, it works under any PKCS#11 client (`pkcs11-tool`, OpenSSL's provider, NSS,
p11-kit), configured from the environment and packaged on its own (`packages.p11-fault`),
outside the cakeys packages. With no plan it is transparent, which a third run of the
reference suite through it proves before any test trusts it to lie.

Each claim in DESIGN §8.1 gets a test stating what a lying module can and cannot make cakeys
accept, §8.2 is updated with whatever falls out, and each tier-4 line of COVERAGE_PLAN.md
becomes one row of a test table.

Not chosen: patching SoftHSM (one module, C, a rebuild per fault), forking `pkcs11-spy` (C,
built to log), p11-kit's filter (mechanisms and slots only), pkcs11-proxy-ng's test hooks (an
in-process mock of its own backend), haskoki's fault APIs (internal to its Haskell tests), and
writing a module: the point is to reuse a correct one.

### A4. The object matrix

Already the first item in OPEN.md. With A1's vocabulary and A3's recorder it becomes: proptest
generates object templates over class, key type, usage bits, `CKA_SENSITIVE`,
`CKA_EXTRACTABLE`, `CKA_ALLOWED_MECHANISMS`; each reference token creates what it can; the
result (mode, schemes, binding, assurance, or the refusal and its code) is committed as a
table. Per the standing rule, a refusal found here is recorded with the real-world keys it
would serve, not removed because no fixture needs it.

**Built for SoftHSM and kryoptic** (2026-11-15), as a fixed grid rather than proptest (a pinned
table has to be deterministic): 1544 objects per token, created straight through cryptoki —
generated, and secret keys also imported (`CKA_LOCAL` false) — then declared as they are and
realised in parallel (`crates/cli/tests/object_matrix/`, about a minute and a half a token). The rows
pin the mode, schemes and binding, the exit code, or the token's refusal to hold the object
(`profiles/coverage/objects/<token>.toml`). Families after the first (2026-11-15): imported
private keys (fixture material, by where the public half is: a public key object,
`CKA_PUBLIC_KEY_INFO`, a certificate, nothing), whose rows also show the immutables the lock
pins, since that is where an import differs from a generated key of the same identity;
certificates (RSA, P-256, P-384, Ed25519, a damaged value); data objects (empty to 4 KiB);
both public and private, the privacy declared or not. Its findings are fixed but one (an EC key
with no public half anywhere); OPEN.md, "Identity coverage". **On tpm2-pkcs11 too**
(2026-11-15): the same grid over swtpm (`crates/cli/tests/tpm2.rs`, never the host's TPM), a
fresh session every 8 objects since tpm2-pkcs11 keeps what it made loaded until finalized,
about 2 minutes. A4 is done; a real HSM's table would come from the cloud test beds.

### A5. Key derivation

**Probe it in caprobe: yes.** Derivation is a capability like wrapping, and the probe covers
only `CKM_ECDH1_DERIVE` with a null KDF today (`derive.ecdh.sealed`, `derive.ecdh.read-only` and the
`derive.key-attribute` note). Of the committed profiles only kryoptic advertises HKDF and SP 800-108
[run]. Write probes to add, each a known-answer test against a host implementation on a scratch
key:

- `CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`;
- the legacy diversification mechanisms real HSM deployments use
  (`CKM_AES_ECB_ENCRYPT_DATA`, `CKM_AES_CBC_ENCRYPT_DATA`, the `CKM_CONCATENATE_*` family);
- `CKM_ECDH1_DERIVE` with a non-null KDF (`CKD_SHA256_KDF`) and shared data.

Capability rows per mechanism, as `derive.ecdh.*` already are: works; derives into a sealed secret;
which key types and usage bits the derived key may take; read-only session; whether
`CKA_DERIVE_TEMPLATE` on the base key is honoured (blocked on the cryptoki array-attribute
patch).

**What the rows are for.** A secret key that can only derive has no commitment today and is
refused (17); OPEN.md lists it among the keys real deployments bring. With a KDF the token can
commit to it: derive from the key under a fixed label into a sealed, sign-only session key,
MAC the label with that, hash the MAC. That is a new scheme with a frozen definition per KDF
(a name such as `kdf-hkdf`), ranked with the other commitments, and the probe rows say which
tokens can compute it. The camigrate planner reads the same rows for derive-based transport.

**Define KDF operations in keys.toml: no, with one parked exception.**

- A derivation is a *use* of a key, like a signature. cakeys verifies the key and hands over
  the URI; the consumer derives. Putting uses in the config would make every KDF parameter
  struct (salt, info, counter layout, PRF data) part of a frozen schema.
- A derived key that is stored on the token is an ordinary object and is declared and pinned as
  one. A derived session key is not an object cakeys can pin; its identity is fixed by the base
  key's identity and the consumer's parameters.
- The commitment above uses a KDF, but as a scheme: the spec only declares `CKA_DERIVE = true`.
- The exception is a *relation*: "object B is KDF(A, parameters)", checkable by re-deriving in a
  session and comparing commitments. That is an instance of OPEN.md's "Asserting how keys
  relate" and is parked there; nothing in this plan needs it, because B4's HUK leaves the token
  by design.

### A6. Cross-tests against other forwarders and a second opinion

**pkcs11-proxy-ng as a forwarder layer.** Packaged in the flake (a Rust workspace with a
protobuf build step; not in nixpkgs), its daemon started per test on a Unix socket by
`nix/test-tokens.sh`, as `p11-kit server` is. Then, as for p11-kit:

- a direct-vs-forwarded test like `tests/p11kit.rs`: the same realisations, the same IDs, the
  same refusals;
- the conformance check through it (`assert_profile_conforms`): its parity claim says the
  backend's profile holds unchanged. Any drift becomes a layer profile
  (`profiles/layers/pkcs11-proxy-ng.toml`), named in keys.toml (`profiles =
  ["pkcs11-proxy-ng"]`), since it cannot be detected from `C_GetInfo` (A0b);
- a note in CAKEYS.md on running a token behind it.

**pkcs11-proxy, optional.** Small (CMake, C); worth it only as the restrictive case: its layer
profile subtracts what its whitelist drops, and cakeys must then refuse (15) everything that
needs those mechanisms, before anything is created. Its plain TCP transport is test-only.

**pkcs11-check, once.** Run against the reference modules as packaged here (patched SoftHSM
2.7, kryoptic 1.5.4, tpm2-pkcs11 1.10 on swtpm). Each finding that bears on what cakeys relies
on (wrap and unwrap, derive, the per-use login, `CKA_TRUSTED`, attribute policy) becomes a
profile note, a test or an OPEN.md item. A report, not a check: its counts move with its own
releases.

Exit: pkcs11-proxy-ng passes the conformance and direct-vs-forwarded tests, with or without a
layer of its own; the pkcs11-check findings are triaged.

## Part B: boot-chain integration tests

### Common ground

- **cakeys' role is unchanged**: it pins and verifies, and prints a URI. The signing tools
  (ukify, sbsign, swtpm_localca, cert_create, pkcs11-tool) use the key through their own
  PKCS#11 stack. Each test's first assertion is that `cakeys check` passed before the tool ran,
  and its negative twin is that a swapped key stops the build with 10 before anything is signed.
- **The lock is the link.** Every test compares what ended up in firmware (a db certificate, a
  ROTPK hash, an EK certificate's issuer) with an ID in keys.lock, computed independently.
- **Tokens**: SoftHSM directly (tests only), SoftHSM behind `p11-kit server` (the path real
  builds are allowed), kryoptic, and where RSA-2048 suffices tpm2-pkcs11 on swtpm.
- **Where the tests live** (decided 2026-11-14): these are slow (KVM boots, and TCG for ARM),
  so they are a `packages.<system>.checks-boot` link farm outside `checks`, like
  `test-nspawn`. `nix flake check` and `checks-crane-only` keep their cost; `checks-boot` runs
  when boot-chain code changes and at the end of a stage, and DEVELOPMENT.md's cadence section
  says so.
- **PINs and modules**: the URI carries neither by default. Each consumer gets the module
  through `lib.mkKeys`' `module` and the PIN through a granted file; a consumer that takes them
  only in the URI gets `check --uri-module --uri-pin source`, and
  `--format pkcs11-provider-pem` wraps the URI for pkcs11-provider (CAKEYS.md, "The contract
  with programs").

### S. Spikes first

| Spike | Question | Kills or reshapes |
|---|---|---|
| S1 | Does `ukify` (systemd 262) sign with a `pkcs11:` key on SoftHSM through `pkcs11-provider` 1.3, and `sbsign` 0.9.5 through the libp11 engine, inside a Nix sandbox? | B1's signer matrix |
| S2 | Does swtpm 0.10's `swtpm_localca` take a PKCS#11 signing key (its config documents a `pkcs11:` URI and `SWTPM_PKCS11_PIN`) with SoftHSM and kryoptic? | B2's issuing path; fallback is nixpkgs' `tpm-ek` test pattern with `openssl x509` |
| S3 | Does nixpkgs' `nixos/tests/optee.nix` run here with an aarch64 guest on the x86_64 host, and how long does it take? Does the cross-compiled cakeys run in it? | Whether B3–B6 are x86-hosted or `aarch64-linux` only |
| S4 | With `TRANSFER_LIST=1` in TF-A and `CFG_TRANSFER_LIST=y` in OP-TEE on QEMU, does BL2's transfer list reach OP-TEE, and can a 32-byte entry ride along? Does data placed in secure RAM by QEMU's `-device loader` survive until BL2? | B4's handoff design |
| S5 | Does `optee_ftpm` build against `opteeQemuAarch64.devkit`, load, and bind `tpm_ftpm_tee` so `/dev/tpmrm0` appears? | B5 |

### B1. Secure Boot and a signed UKI (x86_64, KVM)

**Setup.** One `runNixOSTest`. A `signer` node holds the token and builds; the target is booted
by the test driver from what the signer produced (`create_machine` with OVMF, the ESP image and
a variables file from the shared directory). keys.toml is the SoftHSM twin of
`examples/yubikey-secureboot.toml`: PK, KEK and db, each a private key and its certificate, so
the shipped example's shape is finally exercised in CI.

**Flow.**

1. Provision the token; create the three self-signed certificates with the token keys and
   store them as `CKO_CERTIFICATE` objects; `cakeys lock` everything.
2. A consumer derivation, built in the signer's Nix sandbox as in `checks.vm`, runs
   `signing.check`, then `ukify build` with the db key's URI and certificate.
3. Enrol: `virt-fw-vars` writes PK, KEK and db into an OVMF variables file from the
   certificates read off the token.
4. Boot the target with Secure Boot enforcing.

**Assertions.**

| Kind | Assertion |
|---|---|
| Positive | The target boots; `bootctl status` reports Secure Boot enabled in user mode |
| Lock link | SHA-256 of the db certificate in the target's EFI variables equals the lock's `certhash`; the UKI's Authenticode signer key hashes to the lock's `rfc7093m4` |
| Negative | An unsigned UKI, and one signed by a key that is not in db, do not boot |
| Negative | A different key under the same locator: `check` exits 10 in the sandbox, no UKI is produced |
| Negative | A renewed db certificate over the same key: `certhash` fails (10), `rfc7093m4` still passes |
| Cache caveat | A cached UKI build does not re-contact the token; `--check` does (the existing caveat, shown on a real artefact) |

**B1b, authenticated updates.** PK and KEK private keys exist to sign variable updates, which
B1 never uses. Start the target in setup mode, sign `PK.auth`, `KEK.auth` and `db.auth` with
the token keys (`sign-efi-sig-list` through the engine [todo]), and let systemd-boot enrol them.
A `db` update signed by a non-KEK key is rejected by the firmware.

**B1c, measured boot.** With `virtualisation.tpm.enable`: `ukify --pcr-private-key` signs the
PCR 11 policy with a second token key; the target enrols a LUKS volume to that public key
(`systemd-cryptenroll --tpm2-public-key`) and unlocks only when booted from a UKI whose policy
the token signed. nixpkgs' `systemd-initrd-luks-tpm2` test is the model.

### B2. The HSM as the simulated TPM's manufacturer (x86_64)

This answers "be the root of trust for the QEMU TPM", and it closes the OPEN.md item "Chain
the Attestation Key to the EK certificate".

1. **Issue.** A CA key in the token, pinned by cakeys, signs the swtpm's EK certificate
   (and platform certificate) during `swtpm_setup`, via `swtpm_localca` (S2). The certificate
   lands in the TPM's NV index as on real hardware.
2. **Verify the TPM is ours.** A verifier reads the EK certificate from the guest, checks its
   chain to the CA certificate whose `certhash` the lock pins, and runs
   MakeCredential/ActivateCredential so the guest's Attestation Key is proven to live in the TPM
   holding that EK.
3. **Carry it into cakeys.** `tpm-certify` today pins the AK on first use (DESIGN §8.2). An
   anchored form also records what vouches for the AK. How the lock holds that is discussed
   under "The EK anchor in the lock" below; it is decided when B2 starts.
4. **Quote.** The AK signs a quote over the PCRs; the verifier compares PCR 7 with the value
   predicted from the lock's Secure Boot certificates and PCR 11 with the UKI built in B1. One
   test then states: this machine has a TPM we manufactured, and it booted the image our HSM
   signed.

Negatives: a swtpm provisioned by another CA is refused; an EK certificate copied onto a
different swtpm fails ActivateCredential; an AK created outside the TPM fails.

#### The EK anchor in the lock

The record today is `attestation = { kind, root, id }`: `id` commits to the attested Name and
qualified Name, `root` is the AK's SPKI. Chaining to the EK changes neither. It changes why
`root` is trusted: first use, or a certificate chain to a pinned CA.

| | A new scheme (`tpm-certify-ek`, its own `kind`) | An anchor field on the existing record |
|---|---|---|
| Shape | The EK certificate's issuer enters the ID's encoding under a new domain tag | `attestation.anchor = { kind = "tpm-ek-cert", root = <SRI of the CA> }`; `kind`, `root`, `id` unchanged |
| Fits the freeze rule | Directly: one name, one computation | Also: the ID's computation does not change, so no scheme is edited |
| Existing realisations | The ID changes, and a changed attestation ID is refused even on write (10), so each needs a new object name or a new upgrade rule | Upgrade in place: adding an anchor strengthens, like recording a further scheme (§3.5) |
| Downgrade protection | Free: the existing scheme-downgrade rule (14) | One new compared-field rule: an anchor may be added, never dropped or changed (14) |
| Growth | Multiplies: every way of vouching (EK certificate, vendor AK certificate, IDevID) times every attestation scheme is a name | Adds: anchor kinds and attestation kinds are separate registries |
| What it hashes | Puts a per-device EK or its CA into an ID that the qualified Name already ties to the TPM | Keeps "what was attested" and "who vouches for the signer" apart, which is what they are |
| Assurance | A new kind in the `assurance` table | The anchor becomes an input to `assurance` |

Recommended: the anchor field. The evidence is the same; only the trust in its signer differs,
and the field keeps existing locks upgradable.

**Adding kinds without a lock version change.** This already works and should be kept as the
rule: `kind` is a string checked against a registry at load, and the record refuses unknown
fields, so a lock naming a kind or field an older cakeys does not know is refused by it (17)
instead of being verified at lower strength [src: `config.rs`, `check_realisations`]. A new
attestation or anchor kind is then a registry entry and code, never a schema change, and the
version number is kept for changes of structure. Two things to settle while lock v1 is still a
draft, whichever option wins:

- make `anchor` (or a list, `anchors`) part of the v1 record shape before the freeze, optional
  and empty today, so that adding the first anchor kind later is not itself a structural change;
- state the generic rules once for every kind: unknown is refused, adding is allowed on write,
  dropping or changing is 14.

The chain to the EK is checked when the anchor is recorded (`lock`), not on every `check`:
afterwards the pinned AK carries it, as the pinned Yubico root does for PIV.

### B3. OP-TEE's PKCS#11 TA as a reference token (aarch64 QEMU)

nixpkgs already boots TF-A, OP-TEE and Linux in a NixOS test and lists the PKCS#11 TA's slot
through `libckteec.so` (`nixos/tests/optee.nix` [src]); the TA is on by default for this
platform (`CFG_PKCS11_TA ?= y` [src]). Building on that:

- Run the shared reference suite (`tests/reference/`) against `libckteec.so` in the guest, with
  a `Reference` descriptor for its facts.
- `caprobe probe --write` produces `profiles/modules/optee-pkcs11/4.7.toml`; add a provider only
  if a fix-up turns out to be needed.
- Closes OPEN.md's "More reference tokens: an OP-TEE PKCS#11 TA in QEMU".

The guest needs `secure=on`, which KVM cannot provide, so this is TCG on every host.

**Building for the guest.** cakeys cross-compiles from x86_64 with
`pkgsCross.aarch64-multiplatform` [run, 2026-11-14]: both the regular and the crane build, all
three tools, with the `tpm2` and `ykcs11` features, linking the cross tpm2-tss and sqlite; the
binaries are aarch64 ELF. Not yet run in a guest (S3).

- The test environment in `nix/package-common.nix` (`preCheck`, `postCheck`) now exists only
  where the build can execute its tests. Before, a cross build depended on every token package
  for the host platform although its check phase was off, and nixpkgs' kryoptic does not
  cross-compile. The native derivations are unchanged by this (same `drvPath`). The module
  paths in that environment stay host packages on purpose: the test binaries load them.
- The cross build runs no tests, so the reference suite in the guest (above) is the only test
  of the aarch64 binary. The rest of the guest closure comes from the aarch64 binary cache;
  the firmware (TF-A, OP-TEE, the TAs) cross-builds through nixpkgs' own builders. [todo]
- `checks-boot` takes the guest's cakeys from a `packages.<system>.cakeys-aarch64-cross`
  output, so the cross build is exercised whenever the boot tests are.

### B4. TF-A hands the HUK to OP-TEE

**What upstream does today.** On QEMU, OP-TEE has no platform HUK: `tee_otp_get_hw_unique_key`
is the weak stub returning zeros, compiled only under `CFG_INSECURE`
(`core/kernel/otp_stubs.c` [src]), and TF-A's QEMU platform has no HUK code at all [src]. So
both sides need a patch, kept in `nix/patches/` with a draft under `upstream/` like the others.

**Two different keys.** `plat_get_rotpk_info` returns the hash of the root-of-trust *public*
key that verifies boot images; it is B6. The HUK is a *secret* that seeds OP-TEE's key
derivation. Both can be rooted in the HSM, by different means, and are tested separately.

**Design.**

| Step | Mechanism | Notes |
|---|---|---|
| HSM | `huk-master`, a non-extractable HMAC key pinned by its `commitment` ID. Per-device HUK = HMAC-SHA-256(master, label ‖ device serial) through `C_Sign` | Decided 2026-11-14. Key diversification: the master never leaves the token. `cakeys check` first, then `pkcs11-tool --sign`. The label must be domain-separated from cakeys' commitment label (`<label>/<scheme>/<keyType>/<bits>`), since both are HMACs under the same key; a test asserts no HUK input can equal a commitment input |
| Simulated fuses | QEMU's `-device loader` places the 32 bytes at a fixed secure-RAM address at reset | Injection at run time, so one firmware build serves every HUK. Alternatives: a FIP blob (build time), a semihosting file |
| TF-A BL2 | Reads the value, adds it to the handoff to BL32, then zeroes the source | The zeroing stands in for locking the fuse registers |
| Handoff | A transfer-list entry beside the existing `TL_TAG_OPTEE_PAGABLE_PART` (TF-A's QEMU BL2 already builds a transfer list for OP-TEE [src]) | Variant worth testing later: OP-TEE fetches it from BL31 by SMC at init. OP-TEE's generic `nvmem_huk` driver (HUK from a device-tree nvmem cell [src]) is the upstream-shaped alternative on the OP-TEE side |
| OP-TEE | A platform `tee_otp_get_hw_unique_key` returning the received value; built without `CFG_INSECURE`, so a missing HUK is a boot failure, never zeros | |

**User-space verification**, never exposing the HUK:

1. **Through PKCS#11.** The PKCS#11 TA's token lives in OP-TEE secure storage, whose keys
   derive from the HUK. Create and `lock` a key under HUK A. Reboot with HUK A and the same
   storage: `cakeys verify` is 0. Reboot with HUK B and the same storage: the token is
   unreadable, and cakeys must answer 11 or 16, never 0 and never a silent re-create.
   [todo: which error the TA surfaces]
2. **The exact value.** A small witness TA returns HMAC(TA-unique key, challenge), the key
   coming from the system PTA's `DERIVE_TA_UNIQUE_KEY`. The host recomputes it from the
   injected HUK using OP-TEE's rule, subkey = HMAC-SHA-256(HUK, usage ‖ data)
   (`core/kernel/huk_subkey.c` [src]). This proves the value arrived intact, not merely that
   some stable HUK exists.
3. **The source is gone.** Linux cannot read the injection address; BL33 sees zeros there.

Negatives: no injection means OP-TEE does not boot; a HUK of the wrong length is refused by
BL2.

### B5. The fTPM on the injected HUK

On this platform OP-TEE derives the fTPM's endorsement seed from the HUK and the TA's UUID
(`plat-vexpress/vendor_props.c`, property `com.microsoft.ta.endorsementSeed` [src]), so the
fTPM's Endorsement Key is a function of the HUK the HSM produced.
[todo: `optee_ftpm` reads that property for its EPS]

- Package `optee_ftpm` with the devkit (not in nixpkgs); bind `tpm_ftpm_tee` (S5).
- **EK follows the HUK**: same HUK with wiped fTPM storage gives the same EK; another HUK gives
  another EK. Read from user space with tpm2-tools.
- **tpm2-pkcs11 on the fTPM**: the cakeys TPM suite and `tpm-certify` in the guest, and a new
  observed pair `tpm2-pkcs11/1.10+optee-ftpm` from `caprobe probe --write`.
- **Manufacturing**: a factory boot reads the EK and the HSM CA of B2 issues its certificate
  into the fTPM's NV. A later boot is verified exactly as in B2. A device given the wrong HUK
  has another EK, so its certificate no longer matches and attestation fails: the HSM is the
  root of trust for the TPM twice over, through the seed and through the certificate.
- Stretch: TF-A measured boot (`MEASURED_BOOT=1`, supported by the QEMU platform [src]) with
  the event log reaching the fTPM, and a quote over firmware measurements.

### B6. Trusted Board Boot from the lock

- TF-A's ROTPK hash on QEMU is SHA-256 of the DER SubjectPublicKeyInfo
  (`plat/qemu/qemu/platform.mk` [src]). That is what `rfc7093m4` hashes, so the firmware build
  takes its ROTPK hash from keys.lock through `lib.mkKeys` with no token present, and only the
  signing step needs the token. [todo: assert byte equality for RSA and P-256]
- `cert_create` accepts a `pkcs11:` URI for `ROT_KEY` and the image keys, through the OpenSSL
  `pkcs11` engine with the PIN in `PKCS11_PIN` (`tools/cert_create/src/key.c` [src]).
  [todo: the engine path with nixpkgs' OpenSSL 3.5]
- Assertions: the chain boots with `TRUSTED_BOARD_BOOT=1`; a FIP signed by another key stops in
  BL1; a ROTPK hash from a different lock stops in BL1; a swapped token key stops the build
  with 10.

## What changes in cakeys itself

Mostly tests and Nix. The code changes the plan can already name:

- `profile::baseline`: return values and flags (A1).
- A coverage file, its generator and its check (A1).
- `crates/p11-fault`: a forwarding shim with a fault plan, usable by any PKCS#11 client (A3,
  [FAULT_SHIM.md](FAULT_SHIM.md)).
- A pkcs11-proxy-ng package and, if it drifts, its layer profile (A6).
- Fixes from A2, for example URI escaping if the RFC reading holds.
- Two profiles: `optee-pkcs11/4.7`, `tpm2-pkcs11/1.10+optee-ftpm` (B3, B5).
- An EK-anchored attestation, and the optional anchor slot in the v1 attestation record (B2).
- KDF probes and profile rows; a derive-based commitment scheme (A5).
- Possibly the JSON form of `check` (OPEN.md): signers want the URI and the certificate path
  together.

## Risks

- **Emulated aarch64 is slow.** S3 measures it before anything is built on it. cakeys itself
  cross-compiles; a guest package that does not (as kryoptic today) needs the binary cache or
  an aarch64 builder.
- **The handoff patches are ours to carry.** Kept small and offered upstream; the witness TA
  and the HUK-swap test do not depend on which handoff variant is chosen.
- **OpenSSL engines are on their way out.** `sbsign` and `cert_create` use the engine API;
  prefer provider-based signers (ukify, systemd-sbsign) where both exist and record which path
  each test uses.
- **Test-only token paths.** SoftHSM state in a sandbox is acceptable in tests only
  ([CAKEYS.md](CAKEYS.md), "What real builds may reach"); the p11-kit variant of each test is
  the one that models real use.

## Decisions

Decided 2026-11-14:

- **The boot tests live in `checks-boot`**, outside `checks`.
- **The HUK is diversified by HMAC on the token** (B4).
- **cakeys for the aarch64 guests is cross-compiled** from x86_64 (the build works as of
  2026-11-14); S3 runs the result in a guest.
- **No KDF operations in keys.toml**; caprobe probes KDFs (A5).
- **The lying module is a forwarding shim** in front of a real module, driven by a fault plan,
  not a module of its own (A3); it needs neither A1 nor any other stage first.
- **Forwarders other than p11-kit are cross-tested as layers** (A6), pkcs11-proxy-ng first;
  pkcs11-check is run once as a second opinion, never as a check.

Open:

1. **The EK anchor in the lock** (B2): the anchor field is the working choice, confirmed when
   B2 starts. Before lock v1 freezes, reserve the optional anchor slot and state the generic
   rules for kinds, whichever way it goes.
2. **Order.** Recommended: S1–S5, then A1 and B1 in parallel, then A2, B2, B3, then A3, A5, B4,
   then B5, B6 and A4.
