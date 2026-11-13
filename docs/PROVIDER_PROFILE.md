# Provider Profiles

Q: Can a Provider crate "just" be used to express what subset of PKCS11 the vendor provider is compatible with. Or can we enumerate (plan) these compatibility tests with just the cakeys-pkcs11 crate and pkcs11 SO module?

A: Mostly yes to both, with one firm line.

1. Most of a provider can be data rather than code.

A provider today mixes two kinds of knowledge:

┌───────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬───────────────────────┐
│ Kind            │                                                        Examples                                                        │ Needs code? │
├───────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────┤
│ Capabilities and quirks a │ usable mechanisms; OAEP hashes actually implemented (SoftHSM: SHA-1 only); curves it can generate (kryoptic: no        │ No. A declarative │
│ module shows through │ secp256k1); unwrap-template rules (SoftHSM rejects CKA_VALUE_LEN; kryoptic sets no usage unless asked); raw or DER │ profile can express │
│ PKCS#11 │ Edwards points; whether private keys carry CKA_PUBLIC_KEY_INFO; whether create/delete need the admin (SO) login; │ all of it │
│ │ whether delete really deletes │ │
├───────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────┤
│ Behaviour outside │ tpm2's P-521 point repair; YubiKey attestation and its pinned roots; TPM2_Certify; tpm2_ptool; vendor export/import    │ Yes. This stays in a │
│ PKCS#11, or data that has │ tools │ provider crate        │
│ to be rewritten │                                                                                                                        │ │
└───────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴───────────────────────┘

So a provider crate could shrink to a profile (TOML, embedded or loadable) plus hooks only where code is unavoidable. A vendor whose module needs no fix-ups would need no Rust at all: provider = "<profile>" would be enough. That's a reasonable future step, and it fits the scope rule that vendor knowledge lives outside the core.

2. The compatibility tests can be enumerated, and mostly run, using only cakeys-pkcs11 and the vendor's .so.

Everything in the first row can be probed through the module itself. The reference suite and the cross-reference tests already do this, but only for our four reference tokens. The same checks could be packaged as a probe command run against any module:

- Read-only probes, safe on a production token: the mechanism list and info flags, token flags, the module's version, and how existing objects are encoded (points, CKA_PUBLIC_KEY_INFO, policy defaults).
- Write probes, only on a token marked as scratch in keys.toml and refused otherwise: generating each type and curve; wrapping and unwrapping with each mechanism and OAEP hash; trying unwrap templates; checking which attributes a created or unwrapped key ends up with; deleting and checking the key is really gone; checking visibility across sessions; checking duplicate IDs.
- Output: a generated profile, plus a diff against what a provider claims. That gives us:
  - Conformance: our shipped SoftHSM and kryoptic profiles must equal a fresh probe of each, which would replace hand-maintained provider data.
  - Drift detection: probing a new module build and diffing it against the old profile catches the "we updated the signing server and now it fails" case before it ships.
  - Vendor onboarding: a vendor, or you with a new HSM, can find what works without writing a crate.

Where probing stops:

- Destructive facts on real hardware. ykcs11's delete that leaves the key is only observable by deleting, so on a YubiKey it can only be probed on a scratch slot.
- What a module only claims to do. A module can show behaviour without that being the reason behind it; a probe records observations, not explanations.
- Anything outside PKCS#11: attestation formats, trust anchors, vendor tools. Those still need code.
- Fix-ups. A probe can detect a quirk like tpm2's malformed P-521 point, but only code can repair it.

Effort: roughly 1.5–2k lines and 2–3 weeks: the profile format, about 25 probes, and the scratch-token guard. It would also make MIGRATE's per-module template rules data-driven, which was that plan's main risk.

Should I write this up as a plan (docs/PROVIDERS.md, or a PLAN to-do), and decide whether it comes before or after MIGRATE phase 2?
