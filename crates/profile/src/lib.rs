//! Capability profiles (docs/CAPROBE.md): what a vendor PKCS#11 module can actually do, as
//! data. One profile per vendor SO version, one per layer between cakeys and the token, and a
//! spec baseline generated from the OASIS headers — queried statically, no token touched, so
//! a config and a vendor SO version answer "is 512 HMAC supported?" before a key exists
//! anywhere.
//!
//! The crate is deliberately independent of the rest of cakeys ([`Baseline`], [`Profile`],
//! [`Set`] and [`Effective`] are pure data and algebra over TOML): `cakeys-pkcs11` resolves a
//! token's stack from them when it opens one.
//!
//! The three artifacts: [`Baseline`] (one spec revision's members and classes),
//! [`Profile`] (a module's observed deltas, or a layer's subtractions) and [`Effective`]
//! (their intersection, what [`Verdict`] answers). [`Set`] loads the committed files this
//! build embeds, plus any a caller adds from a directory (D11).

pub mod baseline;
pub mod capability;
pub mod effective;
pub mod embedded;
pub mod names;
pub mod profile;

pub use baseline::Baseline;
pub use capability::{Answer, Capability, Move, On, Row, Way};
pub use effective::{Effective, Verdict};
pub use names::{KeyKind, Operation, Proof};
pub use profile::{AcceptRow, GenerateRow, Manual, MatchInfo, Migration, Mode, PlaintextKind, Profile, Reported};

use std::path::Path;
use std::sync::OnceLock;

/// The process's profile set ([`Set::active`]).
static ACTIVE: OnceLock<Set> = OnceLock::new();

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

    /// Load every `.toml` under `dir` (recursively) and add it, replacing a loaded profile, or
    /// the baseline, of the same name. The order within the directory is stable (sorted by
    /// path), so which file replaces which does not depend on filesystem order.
    ///
    /// # Errors
    ///
    /// The IO error reading the directory, each file's parse error prefixed with its path, or a
    /// baseline of another name than the loaded one.
    pub fn with_dir(self, dir: &Path) -> Result<Set, String> {
        self.load_dir(dir, true)
    }

    /// Load every module profile under `dir` (recursively) as [`Set::with_dir`] does, but only
    /// to add: what keys.toml's `profileDirs` name at run time. A file there may bring a new
    /// module profile, and with it a new family, never a baseline, a layer or hardware profile,
    /// or a name already loaded: the embedded profiles are re-probed on every build, and a
    /// file outside the build must not silently stand in for one.
    ///
    /// # Errors
    ///
    /// As [`Set::with_dir`], and for each file that would replace or is not a module profile.
    pub fn adding_dir(self, dir: &Path) -> Result<Set, String> {
        self.load_dir(dir, false)
    }

    fn load_dir(mut self, dir: &Path, replace: bool) -> Result<Set, String> {
        let mut paths = Vec::new();
        collect(dir, &mut paths).map_err(|e| format!("{}: {e}", dir.display()))?;
        paths.sort();
        for path in paths {
            let at = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
            let text = std::fs::read_to_string(&path).map_err(|e| at(&e))?;
            let value: toml::Value = toml::from_str(&text).map_err(|e| at(&e))?;
            if value.get("baseline").is_some() {
                if !replace {
                    return Err(at(&"a baseline: only the build's own may be loaded"));
                }
                // One baseline is used ([`Set::baseline`]): a directory's replaces the one of its
                // name (a regenerated pkcs11-3.2), and one of another name is refused rather
                // than loaded and never read.
                let b = Baseline::from_toml(&text).map_err(|e| at(&e))?;
                let Some(slot) = self.baselines.iter_mut().find(|(_, loaded)| loaded.baseline == b.baseline) else {
                    let loaded: Vec<&str> = self.baselines.iter().map(|(_, l)| l.baseline.as_str()).collect();
                    return Err(at(&format!(
                        "baseline '{}': only one baseline is used ({}); a directory may replace it, not add another",
                        b.baseline,
                        loaded.join(", ")
                    )));
                };
                *slot = (path.display().to_string(), b);
            } else if value.get("profile").is_some() {
                let p = Profile::from_toml(&text).map_err(|e| at(&e))?;
                if !replace {
                    if p.mode != Mode::Observed {
                        return Err(at(&format!("'{}' is not a module profile (mode = \"observed\")", p.profile)));
                    }
                    if self.profiles.iter().any(|q| q.profile == p.profile) {
                        return Err(at(&format!("'{}' is already loaded: a profile directory only adds", p.profile)));
                    }
                }
                self.add(p);
            } else {
                return Err(at(&"neither a baseline nor a profile"));
            }
        }
        Ok(self)
    }

    /// The set every token open resolves against, built once per process by [`Set::activate`]
    /// or [`Set::activate_embedded`] (ISSUES.md Q24): never built here behind the caller's back,
    /// so an activation that comes too late is an error where the set was first wanted, not a
    /// silently different set.
    ///
    /// # Errors
    ///
    /// No set activated yet.
    pub fn active() -> Result<&'static Set, String> {
        ACTIVE.get().ok_or_else(|| {
            "no capability profile set is active: the tool activates it (Set::activate) right after \
             reading keys.toml, before anything asks for a profile"
                .to_owned()
        })
    }

    /// Build the active set: the embedded profiles plus every module profile under `dirs`
    /// ([`Set::adding_dir`]). Once per process, before the first token is opened.
    ///
    /// # Errors
    ///
    /// What loading refuses, or the set already being in use.
    pub fn activate(dirs: &[std::path::PathBuf]) -> Result<&'static Set, String> {
        Set::activate_replacing(dirs, None)
    }

    /// [`Set::activate`], then every profile under `replacing` loaded over it
    /// ([`Set::with_dir`]): caprobe's `--profiles`, which measures profiles not yet committed.
    ///
    /// # Errors
    ///
    /// What loading refuses, or the set already being in use.
    pub fn activate_replacing(dirs: &[std::path::PathBuf], replacing: Option<&Path>) -> Result<&'static Set, String> {
        let mut set = Set::embedded()?;
        for dir in dirs {
            set = set.adding_dir(dir)?;
        }
        if let Some(dir) = replacing {
            set = set.with_dir(dir)?;
        }
        ACTIVE.set(set).map_err(|_| "the profile set is already in use: activate it once, first".to_owned())?;
        Set::active()
    }

    /// The embedded set as the active one, for a process that loads no profile directory (the
    /// tests, caprobe): the set already active when there is one, so it may be called more than
    /// once.
    ///
    /// # Errors
    ///
    /// [`Set::embedded`]'s parse error.
    pub fn activate_embedded() -> Result<&'static Set, String> {
        if let Some(set) = ACTIVE.get() {
            return Ok(set);
        }
        let set = Set::embedded()?;
        Ok(ACTIVE.get_or_init(|| set))
    }

    fn add(&mut self, p: Profile) {
        match self.profiles.iter().position(|q| q.profile == p.profile) {
            Some(i) => self.profiles[i] = p,
            None => self.profiles.push(p),
        }
    }

    /// The baseline: the embedded one, or the file of its name a [`Set::with_dir`] directory
    /// replaced it with (a directory adds no other).
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

    /// The families of the module profiles (`mode = "observed"`) whose `[match] manufacturer` is
    /// `manufacturer`: how a module that no provider code claims is recognised, and named, from
    /// data alone (docs/CAPROBE.md: a module with no fix-ups needs no Rust). Layers never count.
    #[must_use]
    pub fn module_families(&self, manufacturer: &str) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .profiles
            .iter()
            .filter(|p| p.mode == Mode::Observed && p.r#match.manufacturer.as_deref() == Some(manufacturer))
            .map(Profile::family)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every module profile family loaded, sorted: what a keys.toml `provider` may name besides
    /// the providers with code.
    #[must_use]
    pub fn module_family_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> =
            self.profiles.iter().filter(|p| p.mode == Mode::Observed).map(Profile::family).collect();
        out.sort_unstable();
        out.dedup();
        out
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

/// Every `.toml` file under `dir`, recursively. Symlinked directories are followed (a Nix
/// `symlinkJoin` of profile directories is one), each real directory once: a link back to an
/// ancestor, or a second link to one already read, adds nothing, so a loop ends and no file
/// loads twice.
fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
    collect_once(dir, out, &mut std::collections::BTreeSet::new())
}

fn collect_once(
    dir: &Path,
    out: &mut Vec<std::path::PathBuf>,
    seen: &mut std::collections::BTreeSet<std::path::PathBuf>,
) -> std::io::Result<()> {
    if !seen.insert(std::fs::canonicalize(dir)?) {
        return Ok(());
    }
    // Sorted, so which of two links to one directory is read does not depend on the filesystem.
    let mut paths = std::fs::read_dir(dir)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_once(&path, out, seen)?;
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No set is active until one is activated (ISSUES.md Q24): asking first is an error, not a
    /// silent embedded set that a later activation would then fail against. The embedded
    /// activation may repeat; a second activation of directories is refused. The only test here
    /// that activates: this test binary's set is this test's.
    #[test]
    fn the_set_is_activated_before_it_is_asked_for() {
        assert!(Set::active().err().unwrap().contains("no capability profile set is active"));
        let set = Set::activate_embedded().unwrap();
        assert!(std::ptr::eq(set, Set::active().unwrap()));
        assert!(std::ptr::eq(set, Set::activate_embedded().unwrap()), "the embedded activation repeats");
        assert!(Set::activate(&[]).err().unwrap().contains("already in use"));
    }

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
                "aws-cloudhsm/5.18+hsm2m-fips",
                "aws-cloudhsm/5.18+hsm2m-non-fips",
                "kmsp11/1.9+hsm-fips",
                "kmsp11/1.9+hsm",
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
        assert!(set.find("yubikey").unwrap_err().starts_with("no profile 'yubikey' (loaded: "));
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
        assert_eq!(set.find("softhsm/2.7").unwrap().wrap_oaep().as_deref(), Some(["SHA-1".to_owned()].as_slice()));
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

    /// Probed rows that all answer no answer no; absent ones are unprobed and answer
    /// unknown. (That the emitter keeps the difference is caprobe's test.)
    #[test]
    fn probed_empty_is_not_unprobed() {
        let set = Set::embedded().unwrap();
        let b = set.baseline().unwrap();
        let none = Profile::from_toml(
            "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\"wrap.rsa-oaep.SHA-1\" = { answer = \"no\" }\n",
        )
        .unwrap();
        assert_eq!(none.wrap_oaep(), Some(Vec::new()));
        assert!(matches!(Effective::new(b, Some(&none), &[]).oaep()[0].1, Verdict::No { .. }));
        let unprobed = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        assert_eq!(unprobed.wrap_oaep(), None);
        assert!(matches!(Effective::new(b, Some(&unprobed), &[]).oaep()[0].1, Verdict::Unknown { .. }));
    }

    /// The committed profiles name only what this cakeys knows (review D4): a profile from a newer
    /// cakeys loads with names this one does not, so a misspelt name in a committed one would load
    /// too, and answer nothing.
    #[test]
    fn the_committed_profiles_name_only_known_rows() {
        use crate::capability::{DECRYPT_OAEP, UNWRAP_TEMPLATE, WRAP_OAEP};
        let set = Set::embedded().unwrap();
        let mut seen = 0;
        for p in set.all() {
            for c in p.capabilities.keys() {
                let known = match c {
                    Capability::Prove { binding, key_type, .. } => {
                        !matches!(binding, Proof::Other(_)) && !matches!(key_type, KeyKind::Other(_))
                    }
                    Capability::WrapOaep(h) => WRAP_OAEP.contains(&h.as_str()),
                    Capability::DecryptOaep(h) => DECRYPT_OAEP.contains(&h.as_str()),
                    Capability::UnwrapTemplate(a) => UNWRAP_TEMPLATE.contains(&a.as_str()),
                    Capability::Generate { key_type, .. }
                    | Capability::Import { key_type, .. }
                    | Capability::Export { key_type, .. }
                    | Capability::Unwrap { key_type, .. }
                    | Capability::Create { key: Some((key_type, _)), .. } => !matches!(key_type, KeyKind::Other(_)),
                    _ => true,
                };
                assert!(known, "{}: {c} names what this cakeys does not know", p.profile);
                seen += 1;
            }
        }
        assert!(seen > 100, "{seen} rows");
    }

    /// A profile from a newer cakeys, naming a proof, hashes and a template attribute this one
    /// does not know, loads (ISSUES.md Q28, review D4), and those rows answer nothing: what this
    /// cakeys asks is answered as without them.
    #[test]
    fn a_newer_cakeys_names_load_and_answer_nothing() {
        let rows = "[capabilities]\n\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\" }\n\"decrypt.rsa-oaep.SHA-256\" = { answer = \"no\" }\n\"unwrap.template.CKA_VALUE_LEN\" = { answer = \"yes\" }\n";
        let newer = "\"wrap.rsa-oaep.SHA-384\" = { answer = \"yes\" }\n\"decrypt.rsa-oaep.SHA3-256\" = { answer = \"yes\" }\n\"unwrap.template.CKA_KEY_TYPE\" = { answer = \"no\" }\n\"prove.pop-later.CKK_EC.secp256r1\" = { answer = \"yes\" }\n";
        let head = "profile = \"m/1\"\nmode = \"observed\"\n";
        let known = Profile::from_toml(&format!("{head}{rows}")).unwrap();
        let both = Profile::from_toml(&format!("{head}{rows}{newer}")).unwrap();
        assert_eq!(both.capabilities.len(), known.capabilities.len() + 4);
        assert_eq!(both.wrap_oaep(), known.wrap_oaep());
        assert_eq!(both.decrypt_oaep(), known.decrypt_oaep());
        assert_eq!(both.unwrap_refuse(), known.unwrap_refuse());
        assert_eq!(known.wrap_oaep(), Some(vec!["SHA-1".to_owned()]));
    }

    /// A misspelled key in any section is refused, never ignored: a `[match]` that lost its
    /// version would match by manufacturer alone.
    #[test]
    fn a_misspelled_key_is_refused_in_every_section() {
        let head = "profile = \"m/1\"\nmode = \"observed\"\n";
        for section in [
            "[match]\nmodule_version = \"1.0\"\n",
            "[subtract]\nkey_types = [\"CKK_AES\"]\n",
            "[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmaxbits = 3072\n",
            "[[migration.public-accepts]]\nclass = \"CKO_PUBLIC_KEY\"\nkeytypes = [\"CKK_RSA\"]\n",
        ] {
            let e = Profile::from_toml(&format!("{head}{section}")).unwrap_err();
            assert!(e.contains("unknown field"), "{section}: {e}");
        }
    }

    /// A directory's symlinks to directories are followed, each real directory once: a link to
    /// an ancestor ends (review lib.rs F1), and a second link to a directory already read loads
    /// nothing twice.
    #[test]
    fn a_symlink_loop_in_a_directory_ends() {
        let dir = tempfile::tempdir().unwrap();
        let modules = dir.path().join("modules");
        std::fs::create_dir(&modules).unwrap();
        std::fs::write(modules.join("m.toml"), "profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        std::os::unix::fs::symlink(dir.path(), modules.join("up")).unwrap();
        std::os::unix::fs::symlink(&modules, dir.path().join("again")).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("n.toml"), "profile = \"n/1\"\nmode = \"observed\"\n").unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("linked")).unwrap();
        let mut paths = Vec::new();
        collect(dir.path(), &mut paths).unwrap();
        let names: Vec<_> = paths.iter().map(|p| p.strip_prefix(dir.path()).unwrap().to_owned()).collect();
        assert_eq!(names, [Path::new("again/m.toml"), Path::new("linked/n.toml")]);
        // Loading it adds each profile once: no "already loaded" from a second path to it.
        let set = Set::embedded().unwrap().adding_dir(dir.path()).unwrap();
        assert!(set.find("m/1").is_ok() && set.find("n/1").is_ok());
    }

    /// A directory's baseline replaces the loaded one of its name and is the one answered with;
    /// one of another name is refused, never loaded and left unread (review lib.rs F2).
    #[test]
    fn a_directory_baseline_is_used_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("baseline.toml");
        let committed = embedded::BASELINE_FILES[0].1;
        let newer = committed.replacen("[mechanisms]\n", "[mechanisms]\nCKM_FROM_A_DIRECTORY = 0x80000001\n", 1);
        assert_ne!(newer, committed);
        std::fs::write(&file, &newer).unwrap();
        let set = Set::embedded().unwrap().with_dir(dir.path()).unwrap();
        assert_eq!(set.baselines.len(), 1);
        assert!(set.baseline().unwrap().mechanisms.contains_key("CKM_FROM_A_DIRECTORY"));
        std::fs::write(&file, committed.replacen("baseline = \"pkcs11-3.2\"", "baseline = \"pkcs11-9.9\"", 1)).unwrap();
        let e = Set::embedded().unwrap().with_dir(dir.path()).err().unwrap();
        assert!(e.contains("baseline 'pkcs11-9.9': only one baseline is used (pkcs11-3.2)"), "{e}");
    }

    /// A `--profiles` directory, read recursively: a baseline replaces the embedded one, a
    /// profile of a loaded name replaces it, a new one is added, and a file that is neither is
    /// refused by name.
    #[test]
    fn a_directory_adds_and_replaces() {
        let dir = std::env::temp_dir().join(format!("cakeys-profile-dir-{}", std::process::id()));
        let nested = dir.join("modules");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.join("baseline.toml"), embedded::BASELINE_FILES[0].1).unwrap();
        std::fs::write(dir.join("softhsm.toml"), "profile = \"softhsm/2.7\"\nmode = \"observed\"\npartial = true\n")
            .unwrap();
        std::fs::write(nested.join("m.toml"), "profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        std::fs::write(nested.join("notes.txt"), "not toml at all").unwrap();
        let set = Set::embedded().unwrap().with_dir(&dir).unwrap();
        assert_eq!(set.baselines.len(), 1, "the baseline of its name is replaced");
        assert!(set.baselines[0].0.ends_with("baseline.toml"));
        assert!(set.find("softhsm/2.7").unwrap().partial);
        assert_eq!(set.all().iter().filter(|p| p.profile == "softhsm/2.7").count(), 1);
        assert!(set.find("m").is_ok());
        std::fs::write(nested.join("odd.toml"), "name = \"x\"\n").unwrap();
        let e = Set::embedded().unwrap().with_dir(&dir).err().unwrap();
        assert!(e.contains("odd.toml: neither a baseline nor a profile"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// keys.toml's `profileDirs` only add module profiles: a new family loads, and replacing an
    /// embedded profile, a layer or a baseline is refused.
    #[test]
    fn a_runtime_directory_only_adds_module_profiles() {
        let dir = std::env::temp_dir().join(format!("cakeys-profile-add-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let try_with = |name: &str, text: &str| {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), text).unwrap();
            Set::embedded().unwrap().adding_dir(&dir)
        };
        let set =
            try_with("acme.toml", "profile = \"acme/1\"\nmode = \"observed\"\n[match]\nmanufacturer = \"Acme HSM\"\n")
                .unwrap();
        assert_eq!(set.module_families("Acme HSM"), ["acme"]);
        assert!(set.module_family_names().contains(&"acme"));
        let e = try_with("s.toml", "profile = \"softhsm/2.7\"\nmode = \"observed\"\n").err().unwrap();
        assert!(e.contains("already loaded"), "{e}");
        let e = try_with("l.toml", "profile = \"proxy/1\"\nmode = \"delta\"\n").err().unwrap();
        assert!(e.contains("not a module profile"), "{e}");
        let e = try_with("b.toml", embedded::BASELINE_FILES[0].1).err().unwrap();
        assert!(e.contains("a baseline"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A secret key's generation is decided by the lengths in bytes the probe tried: exactly, never
    /// by interpolation for AES (its lengths are discrete), between two that generated for a type
    /// whose length is free; a layer's `restrict` bounds are in bits, so a length times eight;
    /// and a profile with no row says unknown, never yes from the mechanism alone.
    #[test]
    fn a_secret_keys_generation_is_decided_by_lengths_in_bytes() {
        let set = Set::embedded().unwrap();
        let b = set.baseline().unwrap();
        let module = |rows: &str| {
            Profile::from_toml(&format!("profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n{rows}")).unwrap()
        };
        let aes = module(
            "\"generate.CKK_AES.8\" = { answer = \"no\" }\n\"generate.CKK_AES.16\" = { answer = \"yes\" }\n\
             \"generate.CKK_AES.32\" = { answer = \"yes\" }\n",
        );
        let eff = Effective::new(b, Some(&aes), &[]);
        let verdict = |kt: &str, n: Option<u32>| eff.generate_secret(kt, n);
        assert!(matches!(verdict("CKK_AES", Some(16)), Verdict::Yes { .. }));
        assert!(matches!(verdict("CKK_AES", Some(8)), Verdict::No { .. }));
        // Between two that generated, but AES has no length there.
        assert!(matches!(verdict("CKK_AES", Some(24)), Verdict::Unknown { .. }));
        // No length asked: some length generated.
        assert!(matches!(verdict("CKK_AES", None), Verdict::Yes { .. }));
        // No row for the type at all.
        assert!(matches!(verdict("CKK_DES3", Some(24)), Verdict::Unknown { .. }));
        let free = module(
            "\"generate.CKK_GENERIC_SECRET.16\" = { answer = \"yes\" }\n\
             \"generate.CKK_GENERIC_SECRET.64\" = { answer = \"yes\" }\n",
        );
        let eff = Effective::new(b, Some(&free), &[]);
        assert!(matches!(eff.generate_secret("CKK_GENERIC_SECRET", Some(32)), Verdict::Yes { .. }));
        assert!(matches!(eff.generate_secret("CKK_GENERIC_SECRET", Some(128)), Verdict::Unknown { .. }));
        // Every length refused: the type is no.
        let none = module("\"generate.CKK_SHA256_HMAC.16\" = { answer = \"no\" }\n");
        let eff = Effective::new(b, Some(&none), &[]);
        assert!(matches!(eff.generate_secret("CKK_SHA256_HMAC", None), Verdict::No { .. }));
        // A layer bounds a size in bits: 32 bytes is 256 bits, 48 bytes is not.
        let layer =
            Profile::from_toml("profile = \"l/1\"\nmode = \"delta\"\n[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_AES\"\nmax-bits = 256\n")
                .unwrap();
        let layers = [&layer];
        let eff = Effective::new(b, Some(&aes), &layers);
        assert!(matches!(eff.generate_secret("CKK_AES", Some(32)), Verdict::Yes { .. }));
        assert!(matches!(eff.generate_secret("CKK_AES", Some(48)), Verdict::No { by, .. } if by == "l/1"));
    }

    /// Data detection: the families whose module profiles name a manufacturer; layers (p11-kit)
    /// never count.
    #[test]
    fn module_families_come_from_observed_profiles() {
        let set = Set::embedded().unwrap();
        assert_eq!(set.module_families("SoftHSM"), ["softhsm"]);
        assert_eq!(set.module_families("CloudHSM"), ["aws-cloudhsm"]);
        assert_eq!(set.module_families("PKCS#11 Kit"), Vec::<&str>::new());
        assert_eq!(set.module_families("Nobody"), Vec::<&str>::new());
    }
}
