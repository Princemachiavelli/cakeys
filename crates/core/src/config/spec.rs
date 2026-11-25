//! Specs: how an object is realised on a token (`[specs.<name>]`), and the attributes,
//! origins and locators it carries (docs/CONFIG.md).

use super::{BTreeMap, BTreeSet, Binding, Deserialize, Serialize};

/// A spec's settings for camigrate (`[specs.<s>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecMigrateCfg {
    /// The object never leaves the tokens this spec realises it on: `camigrate` refuses to
    /// export or migrate it from them (15), and an export or migrate without names leaves it out
    /// without the warning a key that cannot move gets. A token's transport key
    /// (`transportWith`) is kept so without it.
    #[serde(default)]
    pub no_export: bool,
}

/// A spec (`[specs.<name>]`): the policy one object is realised with, and the tokens it is
/// realised on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCfg {
    /// The object (`[objects.<name>]`) this spec realises.
    pub object: String,
    /// Policy attributes of the object (`CKA_SIGN = true`, `CKA_ALLOWED_MECHANISMS = [...]`).
    /// Part of the spec digest.
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrValue>,
    /// Policy attributes of a private key's public key object (`CKA_VERIFY = true`, ...): set
    /// when generating, checked on the public object. In the spec digest only when present.
    #[serde(default, rename = "publicAttributes")]
    pub public_attributes: BTreeMap<String, AttrValue>,
    /// What only camigrate reads (`[specs.<s>.migrate]`). Not in the spec digest.
    #[serde(default)]
    pub migrate: SpecMigrateCfg,
    /// The tokens this spec realises the object on, by token name.
    pub tokens: BTreeMap<String, SpecTokenCfg>,
}

impl SpecCfg {
    /// A declared boolean attribute.
    #[must_use]
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.attributes.get(name) {
            Some(AttrValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// The declared `CKA_ALLOWED_MECHANISMS`, if any: the mechanisms the key may run.
    #[must_use]
    pub fn allowed_mechanisms(&self) -> Option<&[String]> {
        match self.attributes.get(crate::attrs::ALLOWED_MECHANISMS) {
            Some(AttrValue::Mechanisms(m)) => Some(m),
            _ => None,
        }
    }
}

/// A policy attribute value: a boolean, or a set of `CKM_*` names (`CKA_ALLOWED_MECHANISMS`),
/// kept sorted and without duplicates so its order never changes a digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AttrValue {
    /// A boolean attribute (`CKA_SIGN = true`).
    Bool(bool),
    /// A mechanism set (`CKA_ALLOWED_MECHANISMS`), sorted and without duplicates.
    Mechanisms(Vec<String>),
}

impl AttrValue {
    /// A mechanism set from `names` in any order: sorted, duplicates dropped.
    pub fn mechanisms(names: impl IntoIterator<Item = String>) -> AttrValue {
        let set: BTreeSet<String> = names.into_iter().collect();
        AttrValue::Mechanisms(set.into_iter().collect())
    }
}

/// One token of a spec (`[specs.<s>.tokens.<t>]`): where the object is found there and how it
/// is held.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecTokenCfg {
    /// The `CKA_LABEL` and `CKA_ID` the object is found under on this token.
    pub locator: Locator,
    /// How the object comes to be on this token ([`KeyOrigin`]). Required for a private or
    /// secret key; anything else is adopted unless it says `import`. Use [`Self::key_origin`].
    #[serde(default)]
    pub origin: Option<KeyOrigin>,
    /// Adopt a private key through its public key object only (no login needed, e.g. to
    /// spare PIV PIN retries). Identity is fully verified; presence and policy of the private
    /// half are not, so this is an explicit per-token opt-in recorded in the lock.
    #[serde(default)]
    pub public_only: bool,
    /// `"token-asserted"`: do not prove possession of the private key, for keys that cannot sign
    /// anything the host can verify. Recorded in the lock; `publicOnly` implies it.
    #[serde(default)]
    pub binding: Option<Binding>,
    /// Opt in to the attestation commitment (§3.7 of docs/DESIGN.md): compute the provider's
    /// attestation scheme for this key on this token (`YubiKey` PIV attestation verified to the
    /// pinned Yubico root; a native `TPM2_Certify` for tpm2-pkcs11) and require it ever after —
    /// a realisation that stops computing it is a scheme downgrade (exit 14). The attestation
    /// ID never replaces the portable one: it is recorded only beside `rfc7093m4` (keys) or a
    /// commitment scheme (secret keys), which is what verifies the same material copied to
    /// another token, where no attestation can exist.
    #[serde(default)]
    pub attestation: bool,
}

impl SpecTokenCfg {
    /// The object's origin on this token: as keys.toml says it, else `adopt` (what load allows
    /// to leave it out: anything but an unadopted private or secret key).
    #[must_use]
    pub fn key_origin(&self) -> KeyOrigin {
        self.origin.unwrap_or(KeyOrigin::Adopt)
    }
}

/// How an object comes to be on a token (`tokens.<t>.origin`, docs/CONFIG.md): which verb, if
/// any, puts it there. Not part of the spec digest: like the locator, it says where, not what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyOrigin {
    /// `cakeys create` generates it here: at most one pair per object, which is where the
    /// material is born and whose policy it is born with.
    Create,
    /// camigrate brings the material here from another token; it is never generated here.
    Import,
    /// It is already here, put there by something cakeys does not run; nothing writes it.
    Adopt,
    /// camigrate brings it here from the file its object's `migrate.file` names, where the
    /// material is born (docs/FILE.md). Several pairs may say it: they all read that one file.
    File,
}

impl KeyOrigin {
    /// The name keys.toml writes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            KeyOrigin::Create => "create",
            KeyOrigin::Import => "import",
            KeyOrigin::Adopt => "adopt",
            KeyOrigin::File => "file",
        }
    }
}

/// Arbitrary user values naming the object on one token. Not part of the spec digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    /// The object's `CKA_LABEL`.
    #[serde(rename = "CKA_LABEL", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Hex-encoded.
    #[serde(rename = "CKA_ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl Locator {
    /// Refuse a locator no search can use, and write its `CKA_ID` in lower case so `0A` and `0a`
    /// name one object. An empty `CKA_ID` is a real object's ID, and stays.
    ///
    /// # Errors
    ///
    /// Why, when it names neither `CKA_LABEL` nor `CKA_ID`, or its `CKA_ID` is not hex.
    pub fn canonicalize(&mut self) -> std::result::Result<(), String> {
        if self.label.is_none() && self.id.is_none() {
            return Err("locator needs CKA_LABEL and/or CKA_ID".into());
        }
        if let Some(id) = &mut self.id {
            if crate::hex::decode(id).is_none() {
                return Err(format!("CKA_ID '{id}' is not hex"));
            }
            id.make_ascii_lowercase();
        }
        Ok(())
    }
}
