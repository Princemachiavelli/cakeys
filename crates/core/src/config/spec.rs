//! The specs: how an object is realised on a token (`[specs.<name>]`), and the attributes,
//! origins and locators that a spec contains (docs/CONFIG.md).

use super::{BTreeMap, BTreeSet, Binding, Deserialize, Serialize};
use crate::known::{Known, Permission, Restriction, Why};

/// A spec's settings for camigrate (`[specs.<s>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecMigrateCfg {
    /// The object never leaves the tokens on which this spec realises it. `camigrate` refuses to
    /// export or migrate it from those tokens (15), and an export or migrate without object names
    /// leaves it out without the warning that a key that cannot move gets. A token's transport
    /// key (`transportWith`) is kept on its tokens in the same way without this setting.
    #[serde(default)]
    pub no_export: bool,
}

/// A spec (`[specs.<name>]`): the policy with which one object is realised, and the tokens on
/// which it is realised.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecCfg {
    /// The object (`[objects.<name>]`) that this spec realises.
    pub object: String,
    /// The policy attributes of the object (`CKA_SIGN = true`, `CKA_ALLOWED_MECHANISMS = [...]`).
    /// They are part of the spec digest.
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrValue>,
    /// The policy attributes of a private key's public key object (`CKA_VERIFY = true`, ...).
    /// They are set when the key is generated, and they are checked on the public object. They
    /// are part of the spec digest only when they are present.
    #[serde(default, rename = "publicAttributes")]
    pub public_attributes: BTreeMap<String, AttrValue>,
    /// The settings that only camigrate reads (`[specs.<s>.migrate]`). They are not part of the
    /// spec digest.
    #[serde(default)]
    pub migrate: SpecMigrateCfg,
    /// The tokens on which this spec realises the object, by token name.
    pub tokens: BTreeMap<String, SpecTokenCfg>,
}

impl SpecCfg {
    /// Returns a declared boolean attribute, where `None` means "not declared" (for a usage, or
    /// for a declaration to check). Code asks about a security attribute through
    /// [`Self::restricted`] and [`Self::permitted`], which decide how an undeclared attribute
    /// counts.
    #[must_use]
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.attributes.get(name) {
            Some(AttrValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Returns a declared boolean attribute, or the fact that it is not declared.
    pub fn known(&self, name: &str) -> Known<bool> {
        Known::or(self.flag(name), Why::Undeclared)
    }

    /// Returns whether the spec leaves the restriction `r` in force. It does unless it declares
    /// the attribute `false`.
    #[must_use]
    pub fn restricted(&self, r: Restriction) -> bool {
        self.known(r.attr()).restricts()
    }

    /// Returns whether the spec grants the permission `p`. It does only if it declares the
    /// attribute `true`.
    #[must_use]
    pub fn permitted(&self, p: Permission) -> bool {
        self.known(p.attr()).permits()
    }

    /// Returns the declared `CKA_ALLOWED_MECHANISMS`, if any: the mechanisms that the key may be
    /// used with.
    #[must_use]
    pub fn allowed_mechanisms(&self) -> Option<&[String]> {
        match self.attributes.get(crate::attrs::ALLOWED_MECHANISMS) {
            Some(AttrValue::Mechanisms(m)) => Some(m),
            _ => None,
        }
    }
}

/// A policy attribute value: a boolean, or a set of `CKM_*` names (`CKA_ALLOWED_MECHANISMS`). The
/// set is kept sorted and without duplicates, so that the order in keys.toml never changes a
/// digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AttrValue {
    /// A boolean attribute (`CKA_SIGN = true`).
    Bool(bool),
    /// A mechanism set (`CKA_ALLOWED_MECHANISMS`), sorted and without duplicates.
    Mechanisms(Vec<String>),
}

impl AttrValue {
    /// Returns a mechanism set from `names` in any order, sorted and with duplicates removed.
    pub fn mechanisms(names: impl IntoIterator<Item = String>) -> AttrValue {
        let set: BTreeSet<String> = names.into_iter().collect();
        AttrValue::Mechanisms(set.into_iter().collect())
    }
}

/// One token of a spec (`[specs.<s>.tokens.<t>]`): where the object is found on that token, and
/// how the token holds it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecTokenCfg {
    /// The `CKA_LABEL` and `CKA_ID` with which the object is found on this token.
    pub locator: Locator,
    /// How the object gets onto this token ([`KeyOrigin`]). It is required for a private or
    /// secret key (except a `publicOnly` adoption). Any other object is adopted unless it says
    /// `import` or `file`. Read it with [`Self::key_origin`].
    #[serde(default)]
    pub origin: Option<KeyOrigin>,
    /// Adopts a private key through its public key object only, so that no login is needed (for
    /// example, to avoid using PIV PIN retries). The identity is fully verified, but the presence
    /// and the policy of the private half are not. So this is an explicit opt-in for each token,
    /// and the lock records it.
    #[serde(default)]
    pub public_only: bool,
    /// `"token-asserted"`: do not prove possession of the private key. It is for keys that cannot
    /// sign anything that the host can verify. The lock records it, and `publicOnly` implies it.
    #[serde(default)]
    pub binding: Option<Binding>,
    /// Opts in to the attestation commitment (§3.7 of docs/DESIGN.md). The run computes the
    /// provider's attestation scheme for this key on this token (a `YubiKey` PIV attestation that
    /// is verified to the pinned Yubico root, or a native `TPM2_Certify` for tpm2-pkcs11) and
    /// requires it from then on. A realisation that no longer computes it is a scheme downgrade
    /// (exit 14). The attestation ID never replaces the portable ID. It is recorded only next to
    /// `rfc7093m4` (for keys) or a commitment scheme (for secret keys), because the portable ID
    /// is what verifies the same material when it is copied to another token, where no
    /// attestation can exist.
    #[serde(default)]
    pub attestation: bool,
}

impl SpecTokenCfg {
    /// Returns the object's origin on this token: the origin that keys.toml states, or otherwise
    /// `adopt`. The load allows the origin to be left out for every object except a private or
    /// secret key that is not a `publicOnly` adoption.
    #[must_use]
    pub fn key_origin(&self) -> KeyOrigin {
        self.origin.unwrap_or(KeyOrigin::Adopt)
    }
}

/// How an object gets onto a token (`tokens.<t>.origin`, docs/CONFIG.md): which verb, if any,
/// puts it there. It is not part of the spec digest, because, like the locator, it describes
/// where the object is and not what the object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyOrigin {
    /// `cakeys create` generates the object on this token. At most one pair of each object has
    /// this origin, and that pair decides where the material is created and with which policy.
    Create,
    /// camigrate brings the material to this token from another token. It is never generated on
    /// this token.
    Import,
    /// The object is already on this token, put there by a tool that cakeys does not run. No
    /// cakeys command writes it.
    Adopt,
    /// camigrate brings the object to this token from the file that the object's `migrate.file`
    /// names, where the material is created (docs/FILE.md). Several pairs may have this origin,
    /// and they all read that one file.
    File,
}

impl KeyOrigin {
    /// Returns the name that keys.toml uses.
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

/// The values, chosen by the user, that name the object on one token. They are not part of the
/// spec digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Locator {
    /// The object's `CKA_LABEL`.
    #[serde(rename = "CKA_LABEL", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The object's `CKA_ID`, encoded as hex.
    #[serde(rename = "CKA_ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl Locator {
    /// Refuses a locator that no search can use, and writes its `CKA_ID` in lower case so that
    /// `0A` and `0a` name one object. An empty `CKA_ID` is the ID of a real object, and it is
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns the reason when the locator names neither `CKA_LABEL` nor `CKA_ID`, or when its
    /// `CKA_ID` is not hex.
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
