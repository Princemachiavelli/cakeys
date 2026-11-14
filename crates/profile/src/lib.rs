//! Capability profiles (docs/PROVIDERS.md): what a vendor PKCS#11 module can actually do, as
//! data. One profile per vendor SO version, one per layer between cakeys and the token, and a
//! spec baseline generated from the OASIS headers — queried statically, no token touched, so
//! a config and a vendor SO version answer "is 512 HMAC supported?" before a key exists
//! anywhere.
//!
//! The crate is deliberately independent of the rest of cakeys ([`Baseline`], [`Profile`],
//! [`Set`] and [`Effective`] are pure data and algebra over TOML): wiring the provider code
//! to read from profiles (the plan's phase 2) is the step that touches existing code, and it
//! is not done yet.
//!
//! The three artifacts: [`Baseline`] (one spec revision's members and classes),
//! [`Profile`] (a module's observed deltas, or a layer's subtractions) and [`Effective`]
//! (their intersection, what [`Verdict`] answers). [`Set`] loads the committed files this
//! build embeds, plus any a caller adds from a directory (D11).

pub mod baseline;
pub mod effective;
pub mod embedded;
pub mod profile;

pub use baseline::Baseline;
pub use effective::{Effective, Verdict};
pub use profile::{AcceptRow, GenerateRow, Manual, MatchInfo, Migration, Mode, PlaintextKind, Profile};

use std::path::Path;

/// The loaded profiles: the embedded set, plus any a caller added. Profiles replace by name
/// (an added "softhsm/2.7" replaces the embedded one), and [`Set::find`] selects by exact name
/// or by family when only one version of it is loaded.
pub struct Set {
    baselines: Vec<(String, Baseline)>,
    profiles: Vec<Profile>,
}

impl Set {
    /// Load the files this build embeds.
    ///
    /// # Errors
    ///
    /// [`Profile::from_toml`] errors for each file that fails, prefixed with its path: an
    /// embedded profile that no longer parses is a commit-time bug, not a runtime condition.
    pub fn embedded() -> Result<Set, String> {
        let mut set = Set { baselines: Vec::new(), profiles: Vec::new() };
        for (path, text) in embedded::BASELINE_FILES {
            let b = Baseline::from_toml(text).map_err(|e| format!("{path}: {e}"))?;
            set.baselines.push(((*path).to_owned(), b));
        }
        for (path, text) in embedded::PROFILE_FILES {
            let p = Profile::from_toml(text).map_err(|e| format!("{path}: {e}"))?;
            set.add(p);
        }
        Ok(set)
    }

    /// Load every `.toml` under `dir` (recursively) and add it, replacing a loaded profile of
    /// the same name. The order within the directory is stable (sorted by path), so which file
    /// replaces which does not depend on filesystem order.
    ///
    /// # Errors
    ///
    /// The IO error reading the directory, or each file's parse error prefixed with its path.
    pub fn with_dir(mut self, dir: &Path) -> Result<Set, String> {
        let mut paths = Vec::new();
        collect(dir, &mut paths).map_err(|e| format!("{}: {e}", dir.display()))?;
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let value: toml::Value = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            if value.get("baseline").is_some() {
                let b = Baseline::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
                self.baselines.push((path.display().to_string(), b));
            } else if value.get("profile").is_some() {
                let p = Profile::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
                self.add(p);
            } else {
                return Err(format!("{}: neither a baseline nor a profile", path.display()));
            }
        }
        Ok(self)
    }

    fn add(&mut self, p: Profile) {
        match self.profiles.iter().position(|q| q.profile == p.profile) {
            Some(i) => self.profiles[i] = p,
            None => self.profiles.push(p),
        }
    }

    /// The first loaded baseline (the embedded one; a directory may add more, in which case
    /// [`Set::find`]-style selection comes with phase 2).
    ///
    /// # Errors
    ///
    /// When no baseline was loaded.
    pub fn baseline(&self) -> Result<&Baseline, String> {
        self.baselines.first().map(|(_, b)| b).ok_or_else(|| "no baseline loaded".to_owned())
    }

    /// Every loaded profile, in load order: what resolution iterates to match modules and
    /// forwarders by their `match` rows.
    #[must_use]
    pub fn all(&self) -> &[Profile] {
        &self.profiles
    }

    /// The profile named `name`, by its exact name ("softhsm/2.7") or, when only one version of
    /// the family is loaded, by its family ("softhsm") — what a keys.toml `provider` names.
    ///
    /// # Errors
    ///
    /// When nothing matches (with the loaded names), or a family matches several versions
    /// (naming the one wanted).
    pub fn find(&self, name: &str) -> Result<&Profile, String> {
        if let Some(p) = self.profiles.iter().find(|p| p.profile == name) {
            return Ok(p);
        }
        let family: Vec<_> = self.profiles.iter().filter(|p| p.family() == name).collect();
        match family.len() {
            0 => Err(format!(
                "no profile '{name}' (loaded: {})",
                self.profiles.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", ")
            )),
            1 => Ok(family[0]),
            _ => Err(format!(
                "several profiles for '{name}': name one exactly: {}",
                family.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }
}

/// Every `.toml` file under `dir`, recursively.
fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded set is the committed state of the world: everything parses, every name is
    /// unique, and the answers the checks rely on hold.
    #[test]
    fn embedded_profiles_load_and_answer() {
        let set = Set::embedded().unwrap();
        assert_eq!(set.baselines.len(), 1);
        let names: Vec<_> = set.profiles.iter().map(|p| p.profile.as_str()).collect();
        assert_eq!(
            names,
            [
                "swtpm",
                "cryptoki/0.12",
                "p11-kit/0.26",
                "kryoptic/1.5",
                "softhsm/2.7",
                "tpm2-pkcs11/1.10+amd-ftpm",
                "tpm2-pkcs11/1.10+swtpm",
                "ykcs11/2.7"
            ]
        );
        // find: exact name, unique family, a family of none, an unknown name.
        assert_eq!(set.find("softhsm/2.7").unwrap().profile, "softhsm/2.7");
        assert_eq!(set.find("softhsm").unwrap().profile, "softhsm/2.7");
        assert!(set.find("yubikey").is_err());
        assert!(set.find("").is_err());

        let b = set.baseline().unwrap();
        let softhsm = set.find("softhsm/2.7").unwrap();
        let p11 = set.find("p11-kit/0.26").unwrap();
        let layers = [p11];
        let eff = Effective::new(b, Some(softhsm), &layers);
        assert!(matches!(eff.mechanism("CKM_AES_KEY_WRAP"), Verdict::No { by, .. } if by == "p11-kit/0.26"));
        // The probe-verified profile carries the full `C_GetMechanismList`, so SHA-512 HMAC is
        // decided Yes where the partial hand profile once left it Unknown.
        assert!(matches!(eff.mechanism("CKM_SHA512_HMAC"), Verdict::Yes { .. }));
        assert_eq!(set.find("softhsm/2.7").unwrap().wrap.oaep.as_deref(), Some(["SHA-1".to_owned()].as_slice()));
        // A partial module profile (no advertisement recorded) answers Unknown, never a guess.
        let partial = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\npartial = true\n").unwrap();
        let eff = Effective::new(b, Some(&partial), &[]);
        assert!(matches!(eff.mechanism("CKM_SHA512_HMAC"), Verdict::Unknown { .. }));

        // The cryptoki layer kills the SHA-512 HMAC key type in an unpatched binding [run];
        // whether this build's binding is patched is crates/pkcs11's runtime check.
        let cryptoki = set.find("cryptoki/0.12").unwrap();
        let cryptoki_layers = [cryptoki];
        let eff = Effective::new(b, Some(softhsm), &cryptoki_layers[..]);
        assert!(matches!(
            eff.generate("CKK_SHA512_HMAC", None, None),
            Verdict::No { by, .. } if by == "cryptoki/0.12"
        ));
        // The migration rows are data: ykcs11's PIV import and tpm2's ptool import.
        let yk = set.find("ykcs11/2.7").unwrap();
        assert_eq!(yk.migration.as_ref().unwrap().plaintext_accepts.len(), 3);
        let tpm2 = set.find("tpm2-pkcs11/1.10+swtpm").unwrap();
        assert_eq!(tpm2.migration.as_ref().unwrap().plaintext_accepts.len(), 3);

        // swtpm caps RSA generation at 3072 bits (D10's hardware layer, [run]).
        let swtpm = set.find("swtpm").unwrap();
        let tpm2 = set.find("tpm2-pkcs11/1.10+swtpm").unwrap();
        let swtpm_layers = [swtpm];
        let eff = Effective::new(b, Some(tpm2), &swtpm_layers[..]);
        assert!(matches!(
            eff.generate("CKK_RSA", None, Some(4096)),
            Verdict::No { by, .. } if by == "swtpm"
        ));
        // The pair profile decides on its own what the probe observed: the refused size and the
        // curves; sizes it never tried answer unknown, not the range the module reports.
        let pair = Effective::new(b, Some(tpm2), &[]);
        assert!(matches!(pair.generate("CKK_RSA", None, Some(4096)), Verdict::No { .. }));
        assert!(matches!(pair.generate("CKK_RSA", None, Some(2048)), Verdict::Yes { .. }));
        assert!(matches!(pair.generate("CKK_RSA", None, Some(8192)), Verdict::No { .. } | Verdict::Unknown { .. }));
        assert!(matches!(pair.curve("secp256k1"), Verdict::No { .. }));
    }

    /// A probed-empty row (`oaep = []`) answers no; an absent one is unprobed and answers
    /// unknown. (That the emitter keeps the difference is caprobe's test.)
    #[test]
    fn probed_empty_is_not_unprobed() {
        let set = Set::embedded().unwrap();
        let b = set.baseline().unwrap();
        let none = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n[wrap]\noaep = []\n").unwrap();
        assert_eq!(none.wrap.oaep, Some(Vec::new()));
        assert!(matches!(Effective::new(b, Some(&none), &[]).oaep()[0].1, Verdict::No { .. }));
        let unprobed = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        assert_eq!(unprobed.wrap.oaep, None);
        assert!(matches!(Effective::new(b, Some(&unprobed), &[]).oaep()[0].1, Verdict::Unknown { .. }));
    }
}
