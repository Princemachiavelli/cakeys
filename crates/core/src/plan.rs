//! What a (spec, token) pair asks for, decided from keys.toml alone: the identity mode, the
//! schemes it computes, how a private key is bound to its identity, and the checks a spec must
//! pass before any token is opened (exit 17).

use crate::attrs;
use crate::config::{AsymmetricKey, AttrValue, Binding, Config, Mode, Object, ObjectKind, SpecCfg, SpecTokenCfg};
use crate::id::{BlockCipher, Commit, Curve, HmacHash, Scheme};
use crate::known::{Known, Permission, Restriction, Why};
use crate::types::{KeyType as Kt, ObjectClass as Class};
use crate::{KmError, Result};
use std::collections::BTreeMap;

/// One (spec, token) pair with everything it refers to.
pub struct Target<'a> {
    /// The spec's name.
    pub spec_name: &'a str,
    /// The spec.
    pub spec: &'a SpecCfg,
    /// The name of the object it realises.
    pub object_name: &'a str,
    /// That object, parsed.
    pub object: Object<'a>,
    /// The token's name.
    pub token_name: &'a str,
    /// The spec's settings for this token.
    pub on_token: &'a SpecTokenCfg,
    /// This spec is its token's transport key (`transportWith`): the lock records its public key.
    pub transport: bool,
}

impl<'a> Target<'a> {
    /// The spec and the object it realises, as named, plus its policy on `token_name`.
    ///
    /// # Errors
    ///
    /// `NotFound` if keys.toml names no such spec, or the spec no such token; `Validation` if
    /// the spec references an unknown object, or `[tokens]` has no entry named `token_name`;
    /// what [`Object::new`] refuses for a `Config` not made by loading.
    pub fn new(cfg: &'a Config, spec_name: &'a str, token_name: &'a str) -> Result<Self> {
        let spec = cfg.specs.get(spec_name).ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}'").into()))?;
        let (object_name, object) = cfg.objects.get_key_value(&spec.object).ok_or_else(|| {
            KmError::Validation(format!("spec '{spec_name}' references unknown object '{}'", spec.object).into())
        })?;
        let on_token = spec
            .tokens
            .get(token_name)
            .ok_or_else(|| KmError::NotFound(format!("spec '{spec_name}' has no token '{token_name}'").into()))?;
        if !cfg.tokens.contains_key(token_name) {
            return Err(KmError::Validation(format!("unknown token '{token_name}'").into()));
        }
        let transport = cfg.tokens.get(token_name).and_then(|t| t.migrate.transport_with.as_deref()) == Some(spec_name);
        // Load parsed it already: this refuses only for a `Config` not made by loading, named
        // as every other error of the pair is.
        let object = Object::new(object)
            .map_err(|e| e.prefixed(format_args!("'{object_name}' (spec '{spec_name}') on token '{token_name}'")))?;
        Ok(Target { spec_name, spec, object_name, object, token_name, on_token, transport })
    }

    /// Identity schemes this spec can compute (from the spec alone), in order of preference:
    /// the first one a realisation computes is its primary scheme. A token lacking a mechanism
    /// may compute fewer.
    #[must_use]
    pub fn schemes(&self) -> Vec<Scheme> {
        match (self.object.class, self.object.key_type) {
            (Class::PrivateKey | Class::PublicKey, _) => vec![Scheme::Rfc7093m4],
            (Class::Certificate, _) => vec![Scheme::Certhash, Scheme::Rfc7093m4],
            (Class::Data, _) => vec![Scheme::Valuehash],
            (_, kt) => match (kt.and_then(block_commits), declared_commits(self)) {
                // No usable usage bit: wrap-rebind (if extractable) computes all of them.
                (Some(all), d) if d.is_empty() => all.iter().map(|c| c.scheme()).collect(),
                (Some(_), d) => d.iter().map(|c| c.scheme()).collect(),
                (None, _) => vec![Scheme::Commitment],
            },
        }
    }
}

impl Target<'_> {
    /// Whether the object is seen only after a login (review 2026-11-24 B-4): the one answer
    /// every verb that looks for it asks before it says the object is not there. The lock's
    /// record of what the token reported (`CKA_PRIVATE` of this realisation) first, then what
    /// the spec declares, then the class: a public key or certificate is public, anything else
    /// private, a data object included (§9.2: unknown restricts). A `publicOnly` adoption is
    /// looked for through its public key.
    #[must_use]
    pub fn needs_login(&self, lock: &crate::config::Lock) -> bool {
        if self.on_token.public_only {
            return false;
        }
        let recorded = lock
            .realisation(self.spec_name, self.token_name)
            .map_or(Known::Unknown(Why::Unrecorded), |r| r.observed(Restriction::Private.attr()));
        match recorded.or_else(|| self.spec.known(Restriction::Private.attr())) {
            Known::Is(private) => private,
            Known::Unknown(_) => !matches!(self.object.class, Class::PublicKey | Class::Certificate),
        }
    }
}

/// How messages name the target: `'<object>' (spec '<spec>') on token '<token>'`.
impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}' (spec '{}') on token '{}'", self.object_name, self.spec_name, self.token_name)
    }
}

/// How `t`'s private key is bound to its identity: proven by signing, deriving or decrypting
/// (`pop-*`) unless the spec opts out (or adopts it publicOnly). `None` for every other class.
/// This is the planned method; the proof records `pop-sign-pin` for `pop-sign` when the token
/// reports the key `CKA_ALWAYS_AUTHENTICATE` (docs/DESIGN.md §3.6).
#[must_use]
pub fn binding(t: &Target) -> Option<Binding> {
    if t.object.class != Class::PrivateKey {
        return None;
    }
    if t.on_token.public_only {
        return Some(Binding::TokenAsserted);
    }
    Some(t.on_token.binding.unwrap_or(Binding::PopSign))
}

/// The binding a realisation of `t` will record, as far as the spec tells: [`binding`], with
/// `pop-sign` as `pop-sign-pin` on a key the spec declares `CKA_ALWAYS_AUTHENTICATE`. What a
/// check before anything is created or moved asks a proof of; a token reporting the attribute
/// undeclared is seen only by the realisation itself.
#[must_use]
pub fn expected_binding(t: &Target) -> Option<Binding> {
    match binding(t) {
        Some(Binding::PopSign) if t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) => Some(Binding::PopSignPin),
        b => b,
    }
}

/// What a realisation's check establishes against a module or token that may lie (the replay
/// analysis in docs/archive/REVIEW-2026-11-13.md). Derived from the class, the recorded binding and the
/// attestation kind, never stored: the lock already holds all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Assurance {
    /// Possession proven over a fresh challenge the host verifies: a `pop-*` binding, or a
    /// nonce-bound attestation (`tpm-certify`). Replaying an earlier answer fails.
    Proof,
    /// A secret key's commitment: the token's deterministic output over a fixed input. It shows
    /// the material is the locked one, but anything that saw the output once can replay it; the
    /// host holds no key to check a fresh challenge with.
    Fingerprint,
    /// A hash of public bytes (public keys, certificates, data objects, and private keys adopted
    /// `token-asserted` or `publicOnly`): whoever has the bytes passes. So does a private data
    /// object's value: a module that saw it once can answer with it.
    Public,
}

impl Assurance {
    /// The name the JSON output and the Nix view use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Assurance::Proof => "proof",
            Assurance::Fingerprint => "fingerprint",
            Assurance::Public => "public",
        }
    }
}

/// The [`Assurance`] of a realisation of an object of `class`, recorded with `binding` and an
/// attestation of `attestation_kind` (the lock record's `kind`).
#[must_use]
pub fn assurance(class: Class, binding: Option<Binding>, attestation_kind: Option<&str>) -> Assurance {
    // TPM2_Certify signs a fresh nonce over the loaded object: proof of presence for any class.
    if attestation_kind == Scheme::TpmCertify.attestation_kind() {
        return Assurance::Proof;
    }
    match (class, binding) {
        (Class::PrivateKey, Some(b)) if b != Binding::TokenAsserted => Assurance::Proof,
        (Class::SecretKey, _) => Assurance::Fingerprint,
        _ => Assurance::Public,
    }
}

/// A private key must be able to prove possession, or say explicitly that it does not. `kind` is
/// the object's type as load parsed it.
fn check_binding(t: &Target, kind: ObjectKind) -> Result<()> {
    let invalid = |why: String| Err(KmError::Validation(format!("{t}: {why}").into()));
    let ed448 = matches!(kind, ObjectKind::Asymmetric { key: AsymmetricKey::Edwards(Curve::Ed448), .. });
    match (binding(t), t.on_token.binding) {
        (_, Some(Binding::PopSignPin)) => invalid(
            "binding = \"pop-sign-pin\" is recorded, not configured: write \"pop-sign\" (the default); \
             a CKA_ALWAYS_AUTHENTICATE key proves it with a PIN per use"
                .into(),
        ),
        (None, Some(b)) => invalid(format!("binding = \"{b}\" applies to private keys only")),
        // publicOnly reads the public key object alone, so it implies "token-asserted": a proof
        // configured beside it is refused, never silently replaced (docs/DESIGN.md §3.6).
        (Some(Binding::TokenAsserted), Some(b)) if t.on_token.public_only && b != Binding::TokenAsserted => {
            invalid(format!("publicOnly cannot prove possession (binding = \"{b}\"): it implies \"token-asserted\""))
        }
        (Some(Binding::PopSign), _) if ed448 => invalid(
            "cakeys has no Ed448 verifier to prove possession with; opt in with binding = \"token-asserted\"".into(),
        ),
        // Only the sign proof has a point for the per-use login (docs/DESIGN.md §3.6).
        (Some(b @ (Binding::PopEcdh | Binding::PopDecrypt | Binding::PopUnwrap)), _)
            if t.spec.flag("CKA_ALWAYS_AUTHENTICATE") == Some(true) =>
        {
            invalid(format!(
                "a CKA_ALWAYS_AUTHENTICATE key needs its PIN per use, and binding = \"{b}\" has no point for \
                 that login: only \"pop-sign\" proves possession with it; or opt in with binding = \
                 \"token-asserted\""
            ))
        }
        (Some(Binding::PopSign), _) if !t.spec.permitted(Permission::Sign) => invalid(
            "proving possession of the private key needs CKA_SIGN = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopEcdh), _) if !matches!(t.object.key_type, Some(Kt::Ec | Kt::EcEdwards)) => {
            invalid("binding = \"pop-ecdh\" proves possession by deriving: it applies to EC private keys only".into())
        }
        (Some(Binding::PopEcdh), _) if t.object.key_type == Some(Kt::EcEdwards) => invalid(
            "binding = \"pop-ecdh\" derives with CKM_ECDH1_DERIVE: it applies to Weierstrass EC keys, not Edwards"
                .into(),
        ),
        (Some(Binding::PopEcdh), _) if !t.spec.permitted(Permission::Derive) => invalid(
            "proving possession by deriving needs CKA_DERIVE = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopDecrypt), _) if t.object.key_type != Some(Kt::Rsa) => invalid(
            "binding = \"pop-decrypt\" proves possession by decrypting: it applies to RSA private keys only".into(),
        ),
        (Some(Binding::PopDecrypt), _) if !t.spec.permitted(Permission::Decrypt) => invalid(
            "proving possession by decrypting needs CKA_DECRYPT = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        (Some(Binding::PopUnwrap), _) if t.object.key_type != Some(Kt::Rsa) => invalid(
            "binding = \"pop-unwrap\" proves possession by unwrapping: it applies to RSA private keys only".into(),
        ),
        (Some(Binding::PopUnwrap), _) if !t.spec.permitted(Permission::Unwrap) => invalid(
            "proving possession by unwrapping needs CKA_UNWRAP = true in the spec attributes; \
             or opt in with binding = \"token-asserted\" on this token"
                .into(),
        ),
        _ => Ok(()),
    }?;
    // A declared allowed list that forbids every mechanism of the proof: the token would refuse
    // each proof (15), so the spec is refused here, as one forbidding every commitment is
    // (review 2026-11-23 A-10).
    if let (Some(b), Some(allowed)) = (binding(t), t.spec.allowed_mechanisms()) {
        let needs = proof_mechanisms(b, kind);
        if !needs.is_empty() && !needs.iter().any(|m| allowed.iter().any(|a| a == m)) {
            return invalid(format!(
                "binding = \"{b}\" proves possession with one of {}, and the spec's CKA_ALLOWED_MECHANISMS \
                 allows none of them; allow one, or opt in with binding = \"token-asserted\" on this token",
                needs.join(", ")
            ));
        }
    }
    Ok(())
}

/// The mechanisms a proof by `binding` may run on a private key of `kind`, one of which the key's
/// `CKA_ALLOWED_MECHANISMS` must allow: the names of the first group of `cakeys_pkcs11`'s
/// `proof_mechanisms`, which its test holds equal. Empty when the binding runs none. `pop-unwrap`'s
/// HMAC runs on the unwrapped session key, which the private key's list does not narrow.
#[must_use]
pub fn proof_mechanisms(binding: Binding, kind: ObjectKind) -> &'static [&'static str] {
    use crate::sig::HashAlg;
    let ObjectKind::Asymmetric { key, .. } = kind else { return &[] };
    match (binding, key) {
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Ec(c)) => match HashAlg::for_curve(c) {
            Some(HashAlg::Sha256) => &["CKM_ECDSA_SHA256", "CKM_ECDSA"],
            Some(HashAlg::Sha384) => &["CKM_ECDSA_SHA384", "CKM_ECDSA"],
            Some(HashAlg::Sha512) => &["CKM_ECDSA_SHA512", "CKM_ECDSA"],
            None => &[],
        },
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Edwards(_)) => &["CKM_EDDSA"],
        (Binding::PopSign | Binding::PopSignPin, AsymmetricKey::Rsa { .. }) => &[
            "CKM_SHA256_RSA_PKCS",
            "CKM_RSA_PKCS",
            "CKM_SHA384_RSA_PKCS",
            "CKM_SHA512_RSA_PKCS",
            "CKM_SHA256_RSA_PKCS_PSS",
            "CKM_SHA384_RSA_PKCS_PSS",
            "CKM_SHA512_RSA_PKCS_PSS",
            "CKM_RSA_PKCS_PSS",
        ],
        (Binding::PopEcdh, _) => &["CKM_ECDH1_DERIVE"],
        (Binding::PopDecrypt, _) => &["CKM_RSA_PKCS_OAEP", "CKM_RSA_PKCS"],
        (Binding::PopUnwrap, _) => &["CKM_RSA_PKCS_OAEP"],
        (Binding::TokenAsserted, _) => &[],
    }
}

/// Declared attributes must be settable booleans (or a mechanism list for `CKA_ALLOWED_MECHANISMS`)
/// that the class can carry (`cakeys_core::attrs`).
fn check_declared(t: &Target, class: Class, declared: &BTreeMap<String, AttrValue>) -> Result<()> {
    for (name, v) in declared {
        let applies = match v {
            AttrValue::Mechanisms(_) if name != attrs::ALLOWED_MECHANISMS => {
                return Err(KmError::Validation(
                    format!("{t}: {name}: only CKA_ALLOWED_MECHANISMS takes a mechanism list").into(),
                ));
            }
            AttrValue::Mechanisms(_) => attrs::has_allowed_mechanisms(class),
            AttrValue::Bool(_) if !attrs::is_declarable_bool(name) => {
                return Err(KmError::Validation(format!("{t}: unsupported policy attribute {name}").into()));
            }
            AttrValue::Bool(_) => attrs::declarable(class, name),
        };
        if !applies {
            return Err(KmError::Validation(format!("{t}: {name} does not apply to {class} objects").into()));
        }
    }
    Ok(())
}

/// Best identity mode achievable from the spec alone; weak modes need a per-token opt-in.
///
/// # Errors
///
/// `Validation` for a spec whose binding, attributes or identity opt-ins do not fit the
/// object's class (checked here, so no object is ever created for an unusable spec).
pub fn plan_mode(t: &Target) -> Result<Mode> {
    let invalid = |why: &str| Err(KmError::Validation(format!("{t}: {why}").into()));
    let kind = t.object.kind();
    check_binding(t, kind)?;
    // Attribute shapes and names, per class: a private key's `publicAttributes` shape its public
    // key object.
    check_declared(t, t.object.class, &t.spec.attributes)?;
    check_declared(t, Class::PublicKey, &t.spec.public_attributes)?;
    if !t.spec.public_attributes.is_empty() && t.object.class != Class::PrivateKey {
        return invalid("publicAttributes apply to private keys only");
    }
    if t.on_token.public_only {
        if t.object.class != Class::PrivateKey {
            return invalid("publicOnly applies to private keys only");
        }
        if !t.spec.attributes.is_empty() {
            return invalid("publicOnly cannot verify private-key policy attributes; leave attributes empty");
        }
    }
    // PIV attests asymmetric keys, TPM2_Certify any TPM-resident object; certificates and data
    // objects are not keys, and no attestation scheme exists for them.
    if t.on_token.attestation && !t.object.class.is_key() {
        return invalid(
            "attestation = true applies to key objects only (PIV attests asymmetric keys, TPM2_Certify any TPM-resident object)",
        );
    }
    let kt = match kind {
        ObjectKind::Asymmetric { .. } | ObjectKind::Certificate | ObjectKind::Data => return Ok(Mode::Direct),
        ObjectKind::Secret { key_type, .. } => key_type,
    };
    let attr = |n: &str| t.spec.flag(n);
    let mode =
        if !declared_commits(t).is_empty() {
            Mode::Commitment
        } else if attr("CKA_EXTRACTABLE") == Some(true) {
            Mode::WrapRebind
        } else {
            // Usage bits that enable commitments the declared allowed mechanisms all forbid.
            let enabled = enabled_commits(t);
            if !enabled.is_empty() {
                let mechs: Vec<&str> = enabled.iter().map(|c| c.mechanism()).collect();
                return Err(KmError::Validation(
                    format!(
                        "{t} has no re-verifiable identity: its CKA_ALLOWED_MECHANISMS allows none of the commitments \
                 its usage bits enable ({}); allow one of them, or declare CKA_EXTRACTABLE = true",
                        mechs.join(", ")
                    )
                    .into(),
                ));
            }
            // The weaker modes this leaves out (computed once and never re-checked) are parked:
            // docs/DESIGN.md §3.4.
            let bits: Vec<&str> = match block_commits(kt) {
                Some(all) => all.iter().map(|c| c.usage()).collect(),
                None => vec!["CKA_SIGN"],
            };
            return Err(KmError::Validation(format!(
            "{t} has no re-verifiable identity (non-extractable, and no usage bit that commits a {kt} key: {}): \
             declare a usage bit that allows a commitment, or CKA_EXTRACTABLE = true",
            bits.join(", ")
        ).into()));
        };
    Ok(mode)
}

/// Commitments the spec's declared usage bits allow, strongest-linking first, and of those the
/// ones its declared `CKA_ALLOWED_MECHANISMS` (if any) lets the key run. Only declared attributes
/// count: a token default never silently changes which identity is computed, and the schemes
/// planned before any object exists are the ones every later run computes and the lock pins.
#[must_use]
pub fn declared_commits(t: &Target) -> Vec<Commit> {
    let permitted =
        |c: &Commit| t.spec.allowed_mechanisms().is_none_or(|allowed| allowed.iter().any(|m| m == c.mechanism()));
    enabled_commits(t).into_iter().filter(permitted).collect()
}

/// Commitments the spec's declared usage bits enable, before its allowed mechanisms narrow them.
fn enabled_commits(t: &Target) -> Vec<Commit> {
    let on = |n: &str| t.spec.flag(n) == Some(true);
    match t.object.key_type.and_then(block_commits) {
        Some(all) => all.iter().copied().filter(|c| on(c.usage())).collect(),
        None => match t.object.key_type.and_then(HmacHash::for_key_type) {
            Some(hash) if on("CKA_SIGN") => vec![Commit::Hmac(hash)],
            _ => vec![],
        },
    }
}

/// The commitments of a block-cipher key type in order of preference (the first computed is
/// the primary scheme), each enabled by its usage bit ([`Commit::usage`]); a wrap-rebind copy
/// computes them all. `None` for the HMAC-committed types.
#[must_use]
pub fn block_commits(key_type: Kt) -> Option<&'static [Commit]> {
    match key_type {
        Kt::Aes => Some(&AES_COMMITS),
        Kt::Des3 => Some(&DES3_COMMITS),
        _ => None,
    }
}

/// AES commitments in order of preference: `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`.
pub const AES_COMMITS: [Commit; 4] =
    [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes), Commit::KcvEcbDecrypt(BlockCipher::Aes), Commit::Kw];

/// DES3 commitments in order of preference: the two check values. `CKM_DES3_CMAC` is not among
/// them: cryptoki 0.12 cannot name it (docs/OPEN.md), so a DES3 key that may only sign or wrap
/// has no re-verifiable identity unless it is extractable.
pub const DES3_COMMITS: [Commit; 2] = [Commit::KcvEcb(BlockCipher::Des3), Commit::KcvEcbDecrypt(BlockCipher::Des3)];

#[cfg(test)]
mod tests {
    use super::*;

    /// The replay table (docs/archive/REVIEW-2026-11-13.md): only a fresh, host-verified answer is a
    /// proof; a secret key's commitment is a fingerprint; public bytes are public.
    #[test]
    fn assurance_follows_the_replay_table() {
        use Assurance::{Fingerprint, Proof, Public};
        let cases = [
            (Class::PrivateKey, Some(Binding::PopSign), None, Proof),
            (Class::PrivateKey, Some(Binding::PopSignPin), None, Proof),
            (Class::PrivateKey, Some(Binding::PopEcdh), None, Proof),
            (Class::PrivateKey, Some(Binding::PopDecrypt), None, Proof),
            (Class::PrivateKey, Some(Binding::PopUnwrap), None, Proof),
            (Class::PrivateKey, Some(Binding::TokenAsserted), None, Public),
            // A replayable attestation upgrades nothing; a nonce-bound one is a proof.
            (Class::PrivateKey, Some(Binding::TokenAsserted), Some("yubico-piv"), Public),
            (Class::PrivateKey, Some(Binding::TokenAsserted), Some("tpm-certify"), Proof),
            (Class::SecretKey, None, None, Fingerprint),
            (Class::SecretKey, None, Some("tpm-certify"), Proof),
            (Class::PublicKey, None, None, Public),
            (Class::Certificate, None, None, Public),
            (Class::Data, None, None, Public),
        ];
        for (class, binding, kind, want) in cases {
            assert_eq!(assurance(class, binding, kind), want, "{class:?} {binding:?} {kind:?}");
        }
        assert_eq!(serde_json::to_string(&Fingerprint).unwrap(), "\"fingerprint\"");
        assert_eq!([Proof, Fingerprint, Public].map(Assurance::name), ["proof", "fingerprint", "public"]);
    }

    /// The AES commitment strength order (docs/DESIGN.md §3.1, finding S15): CMAC, then the
    /// KCVs, then KW. `declared_commits` zips usage bits with it, so the order is load-bearing:
    /// the first enabled scheme is the primary identity.
    #[test]
    fn aes_commit_strength_order_is_pinned() {
        assert_eq!(
            AES_COMMITS,
            [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes), Commit::KcvEcbDecrypt(BlockCipher::Aes), Commit::Kw]
        );
        assert_eq!(AES_COMMITS.map(Commit::usage), ["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"]);
        // DES3: the check values only, encryption first.
        assert_eq!(DES3_COMMITS, [Commit::KcvEcb(BlockCipher::Des3), Commit::KcvEcbDecrypt(BlockCipher::Des3)]);
        assert_eq!(block_commits(Kt::GenericSecret), None);
    }

    /// A `Config` not made by loading keys.toml (which refuses it) may name an object it does
    /// not define: planning a target refuses it (17).
    #[test]
    fn a_spec_of_an_undefined_object_is_refused() {
        let cfg: Config = toml::from_str(
            "[tokens.t]\ntokenLabel = \"t\"\n\n[specs.s]\nobject = \"gone\"\ntokens.t = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\" }\n",
        )
        .unwrap();
        let e = Target::new(&cfg, "s", "t").err().unwrap();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("unknown object 'gone'")), "{e}");
    }

    /// Whether an object is seen only after a login (review 2026-11-24 B-4): the lock's record
    /// first, then the spec's declaration, then the class, a data object no one says anything of
    /// being private (§9.2); a `publicOnly` adoption is looked for by its public key.
    #[test]
    fn needs_login_asks_the_lock_then_the_spec_then_the_class() {
        let needs = |class: &str, attrs: &str, on: &str, recorded: Option<bool>| {
            let ty = match class {
                "CKO_DATA" => "",
                "CKO_CERTIFICATE" => "certificateType = \"CKC_X_509\"\n",
                "CKO_SECRET_KEY" => "keyType = \"CKK_AES\"\nvalueLen = 32\n",
                _ => "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n",
            };
            let cfg: Config = toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\nclass = \"{class}\"\n{ty}\n\
                 [specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\"{on} }}\n"
            ))
            .unwrap();
            let policy = recorded.map_or_else(String::new, |p| format!("CKA_PRIVATE = {p}"));
            let lock: crate::config::Lock = toml::from_str(&format!(
                "version = 1\n[realisations.s.t]\nobject = \"k\"\nlocator = {{ CKA_LABEL = \"x\" }}\n\
                 specDigest = \"sha256-x\"\nmode = \"direct\"\nschemes = []\npolicy = {{ {policy} }}\n"
            ))
            .unwrap();
            Target::new(&cfg, "s", "t").unwrap().needs_login(&lock)
        };
        let data = |attrs, recorded| needs("CKO_DATA", attrs, "", recorded);
        assert_eq!(
            [data("", None), data("CKA_PRIVATE = false", None), data("CKA_PRIVATE = true", None)],
            [true, false, true],
            "a data object: the spec, else private"
        );
        assert_eq!(
            [data("CKA_PRIVATE = true", Some(false)), data("", Some(false)), data("CKA_PRIVATE = false", Some(true))],
            [false, false, true],
            "what the token reported first"
        );
        let key = |class| needs(class, "", "", None);
        assert_eq!(
            ["CKO_PRIVATE_KEY", "CKO_SECRET_KEY", "CKO_PUBLIC_KEY", "CKO_CERTIFICATE"].map(key),
            [true, true, false, false],
            "by class"
        );
        assert!(!needs("CKO_PRIVATE_KEY", "", ", publicOnly = true", None), "publicOnly");
    }

    /// The target `s` on token `t` of an object of type `ty`, with `on` added to its token entry
    /// and `attrs` as its attributes, planned. Built without load, as a test `Config` may be.
    fn planned(ty: &str, attrs: &str, on: &str) -> Result<Mode> {
        let cfg: Config = toml::from_str(&format!(
            "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\n{ty}\n\n[specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
             tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\"{on} }}\n"
        ))
        .unwrap();
        Target::new(&cfg, "s", "t").and_then(|t| plan_mode(&t))
    }

    const EC: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    const RSA: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"";

    /// publicOnly implies `token-asserted`: every proof configured beside it is refused (17),
    /// never recorded `token-asserted` in its place (review plan.rs F1); `token-asserted` itself,
    /// or no binding, plans.
    #[test]
    fn public_only_refuses_every_configured_proof() {
        for (ty, b) in [(EC, "pop-sign"), (EC, "pop-ecdh"), (RSA, "pop-decrypt"), (RSA, "pop-unwrap")] {
            let e = planned(ty, "", &format!(", publicOnly = true, binding = \"{b}\"")).unwrap_err();
            assert!(
                matches!(&e, KmError::Validation(m) if m.contains("publicOnly cannot prove possession")
                    && m.contains(&format!("binding = \"{b}\""))),
                "{b}: {e}"
            );
        }
        for on in [", publicOnly = true, binding = \"token-asserted\"", ", publicOnly = true"] {
            assert_eq!(planned(EC, "", on).unwrap(), Mode::Direct, "{on}");
        }
    }

    /// A proof the declared `CKA_ALLOWED_MECHANISMS` forbids is refused at load (17), like a
    /// commitment it forbids, not at every proof on the token (15) (review 2026-11-23 A-10).
    #[test]
    fn a_proof_the_allowed_mechanisms_forbid_is_refused_at_load() {
        let allow = |attrs: &str, ms: &str| format!("{attrs}, CKA_ALLOWED_MECHANISMS = [{ms}]");
        for (ty, attrs, on, forbidding, allowing) in [
            (EC, "CKA_SIGN = true", "", "\"CKM_ECDH1_DERIVE\"", "\"CKM_ECDSA\""),
            (EC, "CKA_DERIVE = true", ", binding = \"pop-ecdh\"", "\"CKM_ECDSA\"", "\"CKM_ECDH1_DERIVE\""),
            (RSA, "CKA_SIGN = true", "", "\"CKM_RSA_PKCS_OAEP\"", "\"CKM_SHA512_RSA_PKCS_PSS\""),
            (RSA, "CKA_DECRYPT = true", ", binding = \"pop-decrypt\"", "\"CKM_RSA_X_509\"", "\"CKM_RSA_PKCS\""),
            (RSA, "CKA_UNWRAP = true", ", binding = \"pop-unwrap\"", "\"CKM_RSA_PKCS\"", "\"CKM_RSA_PKCS_OAEP\""),
        ] {
            let e = planned(ty, &allow(attrs, forbidding), on).unwrap_err();
            assert!(
                matches!(&e, KmError::Validation(m) if m.contains("CKA_ALLOWED_MECHANISMS allows none of them")),
                "{attrs}{on}: {e}"
            );
            assert_eq!(planned(ty, &allow(attrs, allowing), on).unwrap(), Mode::Direct, "{attrs}{on}");
        }
        let asserted = ", binding = \"token-asserted\"";
        assert_eq!(planned(EC, &allow("CKA_SIGN = true", "\"CKM_ECDH1_DERIVE\""), asserted).unwrap(), Mode::Direct);
        // The curve's hash: a P-384 key signs its proof with CKM_ECDSA_SHA384, not SHA-256.
        let p384 = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"";
        assert!(planned(p384, &allow("CKA_SIGN = true", "\"CKM_ECDSA_SHA256\""), "").is_err());
        assert!(planned(p384, &allow("CKA_SIGN = true", "\"CKM_ECDSA_SHA384\""), "").is_ok());
    }

    /// Ed448 has no verifier, whichever of its names keys.toml spells (review plan.rs F2: the
    /// curve is the parsed one, not a string).
    #[test]
    fn ed448_cannot_prove_by_signing() {
        for curve in ["edwards448", "Ed448"] {
            let ty = format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"{curve}\"");
            let e = planned(&ty, "CKA_SIGN = true", "").unwrap_err();
            assert!(matches!(&e, KmError::Validation(m) if m.contains("no Ed448 verifier")), "{curve}: {e}");
            assert_eq!(planned(&ty, "CKA_SIGN = true", ", binding = \"token-asserted\"").unwrap(), Mode::Direct);
        }
        let ed25519 = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"";
        assert_eq!(planned(ed25519, "CKA_SIGN = true", "").unwrap(), Mode::Direct);
    }

    /// An object type load would refuse names its target, whether it is invalid (17) or
    /// unsupported (15) (review plan.rs F3).
    #[test]
    fn a_refused_object_type_names_its_target() {
        let unsupported = planned("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_RSA\"", "", "").unwrap_err();
        assert!(matches!(&unsupported, KmError::Unsupported(m) if m.starts_with("'k' (spec 's') on token 't': ")));
        let invalid = planned("class = \"CKO_DATA\"\nvalueLen = 3", "", "").unwrap_err();
        assert!(matches!(&invalid, KmError::Validation(m) if m.starts_with("'k' (spec 's') on token 't': ")));
    }

    /// A declared `CKA_ALLOWED_MECHANISMS` narrows the commitments the usage bits enable to the
    /// ones the key may run; when it forbids them all, an extractable key is wrapped and rebound,
    /// any other refused (17) naming the allowed list — never a commitment the token then refuses.
    #[test]
    fn allowed_mechanisms_narrow_the_commitments() {
        let plan = |attrs: &str| {
            let cfg: Config = toml::from_str(&format!(
                "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\n\
                 valueLen = 32\n\n[specs.s]\nobject = \"k\"\nattributes = {{ {attrs} }}\n\
                 tokens.t = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\" }}\n"
            ))
            .unwrap();
            let t = Target::new(&cfg, "s", "t").unwrap();
            (declared_commits(&t), plan_mode(&t))
        };
        let both = "CKA_SIGN = true, CKA_ENCRYPT = true, CKA_EXTRACTABLE = false";
        assert_eq!(plan(both).0, [Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes)]);
        let (commits, mode) = plan(&format!("{both}, CKA_ALLOWED_MECHANISMS = [\"CKM_AES_CMAC\"]"));
        assert_eq!((commits, mode.unwrap()), (vec![Commit::Cmac], Mode::Commitment));
        let (commits, mode) = plan(&format!("{both}, CKA_ALLOWED_MECHANISMS = [\"CKM_AES_ECB\"]"));
        assert_eq!((commits, mode.unwrap()), (vec![Commit::KcvEcb(BlockCipher::Aes)], Mode::Commitment));
        let gcm = "CKA_ALLOWED_MECHANISMS = [\"CKM_AES_GCM\"]";
        let e = plan(&format!("{both}, {gcm}")).1.unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("allows none of the commitments")), "{e}");
        let extractable = "CKA_SIGN = true, CKA_EXTRACTABLE = true";
        assert_eq!(plan(&format!("{extractable}, {gcm}")).1.unwrap(), Mode::WrapRebind);
    }
}
