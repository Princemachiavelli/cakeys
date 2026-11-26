//! The names of what refuses an object: the rules a plan asks before a write ([`Rule`]) and the
//! checks a run makes of a token, a lock, an attestation or a file ([`Check`]). A refusal carries
//! one of them ([`crate::Reason`], [`crate::KmError::check`]), and a JSON row prints its name in
//! the `rule` field. Users and scripts read these names, so each one is stable: a test holds
//! every name to the tables in docs/CAKEYS.md ("Rules and checks"). Rule names are kebab-case
//! words, and check names are dotted (`identity.material`), so the two lists never share a name.

/// One enum of names: the variants with their names, `ALL` in declaration order, `name`,
/// `named` and `Display`.
macro_rules! names {
    ($(#[$enum_doc:meta])* $enum:ident { $($(#[$doc:meta])* $variant:ident = $name:literal,)* }) => {
        $(#[$enum_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $enum {
            $($(#[$doc])* $variant,)*
        }

        impl $enum {
            /// Every one, in declaration order.
            pub const ALL: &[$enum] = &[$($enum::$variant),*];

            /// Its name, as refusals and the JSON rows print it.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $($enum::$variant => $name,)*
                }
            }

            /// The one whose name is `name`, if there is one.
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
    /// A rule a plan asks before a write (docs/CAKEYS.md, "Rules and checks"). The plan and its
    /// refusals live in `cakeys_pkcs11::ops`, which re-exports this enum; the enum is here so that
    /// a refusal's [`crate::Reason`] can name its rule, and so that one test holds the rule names
    /// and the check names apart.
    Rule {
        /// Where the module may place a key (`cakeys_pkcs11::provider::Provider::placement`): 17.
        Placement = "placement",
        /// An attestation the spec opts into, which the provider computes for the class: 15.
        AttestationCover = "attestation-cover",
        /// An attestation of a key that is imported, which the provider gives only for one the
        /// device generated (PIV): 15.
        ImportedAttestation = "imported-attestation",
        /// A key the module generates from its own template only, which it refuses to make as
        /// declared (`cakeys_pkcs11::provider::Provider::generation`): 15 or 17.
        OwnGeneration = "own-generation",
        /// The templates the write sends, as the provider adjusts them
        /// (`cakeys_pkcs11::provider::Provider::template`): the provider's refusal, 15 or 17.
        Templates = "templates",
        /// What the token can do: the mechanisms, the generation, the proof and the commitments, by
        /// its capability profiles or the open token: 15.
        Capability = "capability",
        /// Nothing else under the locator a creation is made under: 13.
        LocatorFree = "locator-free",
        /// A key the lock does not pin already under the locator `create` makes it under: 19.
        UnpinnedExists = "unpinned-exists",
        /// The lock pins material the token does not hold: a new generation could never match: 14.
        PinnedLost = "pinned-lost",
        /// An object only a login shows, asked of a session without one: 16.
        NeedsLogin = "needs-login",
        /// The object holds the identity a delete expects: 14.
        IfMatch = "if-match",
        /// The module does not remove objects of the class: its profile's `delete.<class>` row, or
        /// the provider (`cakeys_pkcs11::provider::Provider::deletion`): 15.
        DeleteRefused = "delete-refused",
        /// What a delete destroyed is still under the locator: 16.
        DeleteKept = "delete-kept",
        /// The lock can be written: 21.
        LockWritable = "lock-writable",
    }
}

names! {
    /// A check that a run makes of what a token, a lock, an attestation or a file says, and that
    /// refuses the object when it fails (docs/CAKEYS.md, "Rules and checks"). Every
    /// [`crate::KmError::Conflict`], [`crate::KmError::Ambiguous`] and
    /// [`crate::KmError::PreconditionFailed`] names the check or the rule that refused it, or says
    /// that its input did not parse ([`crate::Reason`]). The exit code of each refusal is its
    /// error's; the comment on each variant gives the usual one.
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
        /// The spec (its object, locator, `publicOnly` and digest) is the one realised: 14.
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
        /// A second spec of the same token object does not realise it weaker than the first spec
        /// did: 14.
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

        // The host path (camigrate's `host` and `file` moves).
        /// The key that the source wrapped for the host unwraps under the host's key: 13.
        HostUnwraps = "host.unwraps",
        /// The plaintext key that the host holds is a key of the object's declared type: 13.
        HostKeyType = "host.key-type",

        // camigrate's moves.
        /// A sealed bundle's wrapped key unwraps on the target, so the bundle is intact and was
        /// wrapped to the target's transport key: 13, or 16 where the module says only that the
        /// unwrap failed. A dry run defers it: only the run's unwrap decides it.
        ImportUnwraps = "import.unwraps",
        /// What a move hands over or unwraps is the key that the lock pins: its IDs (10) and its
        /// proof of possession (13). A dry run defers it: only the moved key decides it.
        ImportIdentity = "import.identity",
        /// The transport key that a sealed move wraps to is the one that the lock pins on the
        /// target, under a spec that keys.toml names, and a bundle is made for that target and
        /// sealed to that key: 10 where the key's hash differs, 14 otherwise.
        ImportTransport = "import.transport",
        /// The lock pins what a move checks the moved object by: its IDs, its type, the scheme
        /// that pairs a key with its certificate, and a locked key for a key file's identity: 14.
        ImportLocked = "import.locked",
        /// An EC or Edwards key that a bundle file carries is bound by a proof of possession,
        /// because a `token-asserted` binding would rest on the public key that the bundle
        /// itself names: 14.
        ImportBinding = "import.binding",
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

    /// Each name is the name of one rule or one check, and stays so. Rule names are kebab-case
    /// words and check names are dotted words, both lowercase, so no name is used twice. The
    /// tables in docs/CAKEYS.md ("Rules and checks") list every name in the order of `ALL`, so a
    /// renamed, added or removed rule or check changes the doc in the same diff.
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
