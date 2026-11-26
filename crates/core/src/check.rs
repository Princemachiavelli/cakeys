//! The names of the rules and the checks that can refuse an object. A [`Rule`] is a rule that a
//! plan checks before a write. A [`Check`] is a check that a run makes of a token, a lock, an
//! attestation or a file. A refusal carries one of these names ([`crate::Reason`],
//! [`crate::KmError::check`]), and a JSON row prints the name in its `rule` field. Users and
//! scripts read these names, so no name may change: a test compares every name with the tables
//! in docs/CAKEYS.md ("Rules and checks"). Rule names are kebab-case words, and check names are
//! dotted (`identity.material`), so the two lists never share a name.

/// Defines one enum of names: the variants with their names, the constant `ALL` with every
/// variant in declaration order, the methods `name` and `named`, and an implementation of
/// `Display`.
macro_rules! names {
    ($(#[$enum_doc:meta])* $enum:ident { $($(#[$doc:meta])* $variant:ident = $name:literal,)* }) => {
        $(#[$enum_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $enum {
            $($(#[$doc])* $variant,)*
        }

        impl $enum {
            /// Every variant, in declaration order.
            pub const ALL: &[$enum] = &[$($enum::$variant),*];

            /// Returns the variant's name, as refusals and the JSON rows print it.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $($enum::$variant => $name,)*
                }
            }

            /// Returns the variant whose name is `name`, or `None` if no variant has that name.
            #[must_use]
            pub fn named(name: &str) -> Option<$enum> {
                $enum::ALL.iter().copied().find(|v| v.name() == name)
            }
        }

        impl std::fmt::Display for $enum {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

names! {
    /// A rule that a plan checks before a write (docs/CAKEYS.md, "Rules and checks"). The plan and
    /// its refusals are in `cakeys_pkcs11::ops`, which re-exports this enum. The enum is defined
    /// in this crate so that a refusal's [`crate::Reason`] can name its rule, and so that one test
    /// can check that no rule name is also a check name.
    Rule {
        /// The module allows a key in the place where the write puts it
        /// (`cakeys_pkcs11::provider::Provider::placement`): 17.
        Placement = "placement",
        /// The provider can compute, for the object's class, the attestation that the spec opts
        /// into: 15.
        AttestationCover = "attestation-cover",
        /// The spec does not ask for an attestation of an imported key when the provider attests
        /// only a key that the device generated (PIV): 15.
        ImportedAttestation = "imported-attestation",
        /// The module can generate the key as the spec declares it. A module that generates a key
        /// only from its own template refuses a declared template
        /// (`cakeys_pkcs11::provider::Provider::generation`): 15 or 17.
        OwnGeneration = "own-generation",
        /// The provider accepts the templates that the write sends, after it adjusts them
        /// (`cakeys_pkcs11::provider::Provider::template`). The exit code is the one of the
        /// provider's refusal: 15 or 17.
        Templates = "templates",
        /// The token can do what the write needs: the mechanisms, the generation, the proof and
        /// the commitments, according to its capability profiles or to the open token: 15.
        Capability = "capability",
        /// No other object is under the locator under which a creation puts the new object: 13.
        LocatorFree = "locator-free",
        /// No key that the lock does not pin is already under the locator under which `create`
        /// puts the new key: 19.
        UnpinnedExists = "unpinned-exists",
        /// The lock does not pin material that the token does not hold, because a newly generated
        /// key could never match the pinned material: 14.
        PinnedLost = "pinned-lost",
        /// The run does not look for an object that only a login shows in a session without a
        /// login: 16.
        NeedsLogin = "needs-login",
        /// The object has the identity that a delete expects: 14.
        IfMatch = "if-match",
        /// The module can remove objects of the class, according to its profile's
        /// `delete.<class>` row or to the provider (`cakeys_pkcs11::provider::Provider::deletion`):
        /// 15.
        DeleteRefused = "delete-refused",
        /// The object that a delete destroyed is no longer under the locator: 16.
        DeleteKept = "delete-kept",
        /// The lock can be written: 21.
        LockWritable = "lock-writable",
    }
}

names! {
    /// A check that a run makes of the data that a token, a lock, an attestation or a file
    /// provides, and that refuses the object when it fails (docs/CAKEYS.md, "Rules and checks").
    /// Every [`crate::KmError::Conflict`], [`crate::KmError::Ambiguous`] and
    /// [`crate::KmError::PreconditionFailed`] names the check or the rule that refused the object,
    /// or says that its input did not parse ([`crate::Reason`]). The exit code of a refusal is the
    /// code of its error. The comment on each variant states the condition that passes and, after
    /// the colon, the usual exit code when it fails.
    Check {
        // Identity and proof of possession.
        /// The token's material hashes to the IDs that the lock pins for the object: 10.
        IdentityMaterial = "identity.material",
        /// The private key signed a fresh challenge, and the signature verifies under the public
        /// key that the identity is computed from (`pop-sign`): 13.
        PopSign = "pop.sign",
        /// The private key derived the secret that the host derived with the public key
        /// (`pop-ecdh`): 13.
        PopEcdh = "pop.ecdh",
        /// The private key decrypted a fresh challenge that the host encrypted to the public key
        /// (`pop-decrypt`): 13.
        PopDecrypt = "pop.decrypt",
        /// The private key unwrapped a fresh secret that the host wrapped to the public key
        /// (`pop-unwrap`): 13.
        PopUnwrap = "pop.unwrap",

        // The public half and the certificate.
        /// The public key that a token reports, or that a certificate or a file holds, decodes as
        /// a key of the object's declared type and curve: 13.
        PublicKeyType = "public.key-type",
        /// A public key object under the locator holds the private key's public key, and exposes
        /// it: 13.
        PublicSameKey = "public.same-key",
        /// The `CKA_PUBLIC_KEY_INFO` that the token reports for a key is the key's own material:
        /// 13.
        PublicKeyInfo = "public.key-info",
        /// A certificate object's `CKA_VALUE` is a DER X.509 certificate: 13.
        CertificateDecodes = "certificate.decodes",

        // One object, one token, one pair.
        /// One object of the class matches the locator: 12.
        LocatorUnique = "locator.unique",
        /// One private key on the token carries the key's `CKA_ID`: 12.
        CkaIdUnique = "cka-id.unique",
        /// One token of the module carries the token label: 12.
        TokenUnique = "token.unique",
        /// The address on the command line selects one (spec, token) pair: 12.
        AddressUnique = "address.unique",

        // The object against its spec.
        /// The object's class, key type, curve, size and certificate type are the ones the spec
        /// declares: 13.
        ObjectType = "object.type",
        /// Each attribute that the spec declares has the declared value on the token: 13.
        PolicyAttribute = "policy.attribute",

        // The lock's rules (crates/core/spec/lock.qnt; crates/core/tests/lock_mbt.rs).
        /// The object's type in keys.toml is the type the lock recorded: 14.
        LockType = "lock.type",
        /// The spec (its object, locator, `publicOnly` and digest) is the spec that the lock
        /// recorded for the realisation: 14.
        LockSpec = "lock.spec",
        /// The identity mode is at least the mode the lock recorded: 14.
        LockMode = "lock.mode",
        /// The proof of possession is at least the binding the lock recorded: 14.
        LockBinding = "lock.binding",
        /// The attestation has the kind and the root that the lock recorded: 14.
        LockAttestationAnchor = "lock.attestation-anchor",
        /// The attestation ID is the one the lock recorded under the same root: 10.
        LockAttestationId = "lock.attestation-id",
        /// The attestation that the lock recorded is still computed: 14.
        LockAttestationKept = "lock.attestation-kept",
        /// Every scheme that the lock recorded for the realisation is still computed: 14.
        LockSchemesKept = "lock.schemes-kept",
        /// The immutables fixed when the object was made (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`,
        /// `CKA_ALWAYS_SENSITIVE`) are not weaker than the lock recorded: 14.
        LockImmutables = "lock.immutables",
        /// The policy attributes and immutables that the token reports are the ones the lock
        /// recorded: 14.
        LockAttributes = "lock.attributes",
        /// The IDs computed now share a scheme with the IDs the lock pins, so they can be
        /// compared: 14.
        LockSharedScheme = "lock.shared-scheme",
        /// The lock records a realisation of the spec on the token: 14.
        LockRealised = "lock.realised",
        /// No other object of the class in the lock has the same material: 14.
        LockOneName = "lock.one-name",
        /// The lock pins IDs for an object that is imported, so the imported material can be
        /// checked: 14.
        LockImportIds = "lock.import-ids",
        /// A second spec of the same token object does not realise the object with less than the
        /// first spec established: 14.
        LockSameObject = "lock.same-object",

        // Attestation chains (PIV device certificates, TPM EK certificates).
        /// Each certificate of the chain is valid at the time it is judged at: 13.
        ChainValidity = "chain.validity",
        /// Each issuer is a CA that may sign certificates (`basicConstraints`, its `pathLen`, and
        /// `keyCertSign` when it has a `keyUsage`): 13.
        ChainCa = "chain.ca",
        /// No certificate of the chain has a critical extension that cakeys does not process: 13.
        ChainCriticalExtension = "chain.critical-extension",
        /// The chain has no more links than its attestation allows: 13.
        ChainLength = "chain.length",
        /// The chain ends at a pinned root: 13.
        ChainAnchor = "chain.anchor",
        /// Each certificate's signature verifies under its issuer's key, with the algorithm that
        /// the signed part of the certificate names: 13.
        ChainSignature = "chain.signature",

        // Attestation.
        /// The provider attests with the scheme it advertises: 13.
        AttestScheme = "attest.scheme",
        /// The PIV slot's attestation certificate was issued by the device's attestation
        /// certificate: 13.
        AttestPivSlotByDevice = "attest.piv.slot-by-device",
        /// The PIV slot's attestation certificate names the object's public key: 13.
        AttestPivSlotKey = "attest.piv.slot-key",
        /// One certificate on the PIV token is the slot's, or the device's, attestation
        /// certificate: 12.
        AttestPivUnique = "attest.piv.unique",
        /// The TPM's Attestation Key is a cakeys Attestation Key: one key of its label, a
        /// restricted P-256 ECDSA-SHA256 signing key fixed to the TPM and its parent, with a
        /// public key: 13.
        AttestTpmAk = "attest.tpm.ak",
        /// The TPM's statement is a certify statement: 13.
        AttestTpmStatement = "attest.tpm.statement",
        /// The certify statement names this run's nonce as its qualifying data: 13.
        AttestTpmNonce = "attest.tpm.nonce",
        /// The Name that the statement attests is the Name of the object's public area, as the
        /// module or the store reports it and as the TPM loaded it: 13.
        AttestTpmName = "attest.tpm.name",
        /// The statement's signature verifies against the Attestation Key: 13.
        AttestTpmSignature = "attest.tpm.signature",
        /// The statement's qualified signer is the Attestation Key: 13.
        AttestTpmSigner = "attest.tpm.signer",
        /// The key in the attested public area is the object's key, of the same kind, and a
        /// certified secret key computes the object's commitment: 13.
        AttestTpmMaterial = "attest.tpm.material",
        /// What the module reports as `CKA_LOCAL` and `CKA_EXTRACTABLE` is what the TPM
        /// certified: 13.
        AttestTpmImmutables = "attest.tpm.immutables",
        /// The EK certificate names the purpose `tcg-kp-EKCertificate` and this TPM's
        /// endorsement key: 13.
        AttestTpmEkCertificate = "attest.tpm.ek-certificate",
        /// The TPM activates a credential that was made for the Attestation Key and the
        /// endorsement key, and so recovers the credential's secret. This shows that the two keys
        /// are in the same TPM: 13.
        AttestTpmCredential = "attest.tpm.credential",

        // The host path (camigrate's `host` and `file` moves).
        /// The key that the source wrapped for the host unwraps under the host's key: 13.
        HostUnwraps = "host.unwraps",
        /// The plaintext key that the host holds is a key of the object's declared type: 13.
        HostKeyType = "host.key-type",

        // camigrate's moves.
        /// A sealed bundle's wrapped key unwraps on the target, so the bundle is intact and was
        /// wrapped to the target's transport key: 13, or 16 when the module reports only that the
        /// unwrap failed. A dry run does not make this check, because only the real unwrap can
        /// decide it.
        ImportUnwraps = "import.unwraps",
        /// The key that a move hands over or unwraps is the key that the lock pins: its IDs (10)
        /// and its proof of possession (13). A dry run does not make this check, because only the
        /// moved key can decide it.
        ImportIdentity = "import.identity",
        /// The transport key that a sealed move wraps to is the one that the lock pins on the
        /// target, under a spec that keys.toml names, and a bundle is made for that target and
        /// sealed to that key: 10 where the key's hash differs, 14 otherwise.
        ImportTransport = "import.transport",
        /// The lock pins everything with which a move checks the moved object: its IDs, its type,
        /// the scheme that pairs a key with its certificate, and, for the identity of a key file,
        /// a locked key: 14.
        ImportLocked = "import.locked",
        /// An EC or Edwards key that a bundle file carries is bound by a proof of possession,
        /// because a `token-asserted` binding would depend only on the public key that the bundle
        /// itself names: 14.
        ImportBinding = "import.binding",

        // caprobe's probes.
        /// The key that a probe's move brings back is the key that it moved: the host's check
        /// value of an AES key, or the commitment that the module computes: 13.
        ProbeSameKey = "probe.same-key",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names of the rules and the checks in docs/CAKEYS.md's "Rules and checks", in the
    /// order of the two tables: each table row starts with the name in backticks.
    fn documented() -> (Vec<String>, Vec<String>) {
        let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/CAKEYS.md")).unwrap();
        let section = doc.split("\n## Rules and checks\n").nth(1).expect("docs/CAKEYS.md has \"## Rules and checks\"");
        let section = section.split("\n## ").next().unwrap_or(section);
        let names = section
            .lines()
            .filter_map(|l| l.strip_prefix("| `")?.split_once('`').map(|(n, _)| n.to_owned()))
            .filter(|n| n != "name");
        names.partition(|n| !n.contains('.'))
    }

    /// Each name belongs to exactly one rule or one check. Rule names are kebab-case words and
    /// check names are dotted words, both in lowercase, so no name is used twice. The tables in
    /// docs/CAKEYS.md ("Rules and checks") must list every name in the order of `ALL`, so a
    /// renamed, added or removed rule or check must change the document in the same diff.
    #[test]
    fn check_names_are_stable_and_disjoint_from_rules() {
        let word =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        let rules: Vec<&str> = Rule::ALL.iter().map(|r| r.name()).collect();
        let checks: Vec<&str> = Check::ALL.iter().map(|c| c.name()).collect();
        for r in &rules {
            assert!(word(r), "the rule name {r:?} is not one kebab-case word");
        }
        for c in &checks {
            assert!(c.split('.').count() >= 2 && c.split('.').all(word), "the check name {c:?} is not dotted words");
        }
        let all: std::collections::BTreeSet<&str> = rules.iter().chain(&checks).copied().collect();
        assert_eq!(all.len(), rules.len() + checks.len(), "a name is used twice among {rules:?} and {checks:?}");
        for c in Check::ALL {
            assert_eq!(Check::named(c.name()), Some(*c));
        }
        for r in Rule::ALL {
            assert_eq!(Rule::named(r.name()), Some(*r));
        }
        let (doc_rules, doc_checks) = documented();
        assert_eq!(doc_rules, rules, "docs/CAKEYS.md's rules (left) are not Rule::ALL (right)");
        assert_eq!(doc_checks, checks, "docs/CAKEYS.md's checks (left) are not Check::ALL (right)");
    }
}
