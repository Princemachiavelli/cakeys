//! Capability profiles (docs/CAPROBE.md) record, as data, what a vendor PKCS#11 module can
//! actually do. There is one profile for each vendor SO version, one profile for each layer
//! between cakeys and the token, and one spec baseline that is generated from the OASIS headers.
//! The profiles are queried statically, without access to any token, so a config and a vendor SO
//! version can answer a question such as "is SHA-512 HMAC supported?" before any key exists.
//!
//! The crate is deliberately independent of the rest of cakeys. [`Baseline`], [`Profile`],
//! [`Set`] and [`Effective`] are plain data that is read from TOML, together with the functions
//! that combine that data. `cakeys-pkcs11` resolves a token's stack from them when it opens a
//! token.
//!
//! The crate has three artifacts. A [`Baseline`] holds the members and classes of one spec
//! revision. A [`Profile`] holds the deltas that were observed for a module, or the subtractions
//! of a layer. An [`Effective`] is the intersection of a baseline and its profiles, and it answers
//! each query with a [`Verdict`]. A [`Set`] loads the committed files that this build embeds, plus
//! any files that a caller adds from a directory (D11).

pub mod baseline;
pub mod capability;
pub mod effective;
pub mod embedded;
pub mod names;
pub mod profile;
pub mod regenerate;

pub use baseline::Baseline;
pub use capability::{Answer, By, Capability, DEVICE_FAILED_RV, Move, On, Row, Way, names_device_failure};
pub use effective::{Effective, Verdict};
pub use names::{KeyKind, Proof};
pub use profile::{
    AcceptRow, GenerateRow, Manual, MatchInfo, MechanismInfo, Migration, Mode, PlaintextKind, Profile, Reported,
    Untested, Why,
};

use std::path::Path;
use std::sync::OnceLock;

/// The profile set of this process, which [`Set::active`] returns.
static ACTIVE: OnceLock<Set> = OnceLock::new();

/// The loaded profiles: the embedded set, plus any profiles that a caller added. A profile
/// replaces a loaded profile of the same name (an added "softhsm/2.7" replaces the embedded one).
/// [`Set::find`] selects a profile by its exact name, or by its family when only one version of
/// that family is loaded.
pub struct Set {
    /// The one baseline that the set uses: the embedded baseline, or a baseline of the same name
    /// from a directory. Only one baseline is ever allowed, so the set stores only one (review
    /// 2026-11-23 A-13).
    baseline: Option<Baseline>,
    profiles: Vec<Profile>,
}

impl Set {
    /// Load the files this build embeds.
    ///
    /// # Errors
    ///
    /// Returns the [`Profile::from_toml`] error of the first file that does not parse, prefixed
    /// with the file's path. An embedded profile that no longer parses is a bug in the commit,
    /// not a condition that can arise at run time.
    pub fn embedded() -> Result<Set, String> {
        let mut set = Set { baseline: None, profiles: Vec::new() };
        for (path, text) in embedded::BASELINE_FILES {
            let b = Baseline::from_toml(text).map_err(|e| format!("{path}: {e}"))?;
            if set.baseline.replace(b).is_some() {
                return Err(format!("{path}: only one baseline is used"));
            }
        }
        for (path, text) in embedded::PROFILE_FILES {
            let p = Profile::from_toml(text).map_err(|e| format!("{path}: {e}"))?;
            set.add(p);
        }
        Ok(set)
    }

    /// Loads every `.toml` file under `dir` (recursively) and adds it. A file replaces a loaded
    /// profile, or the baseline, of the same name. The files are read in a stable order (sorted
    /// by path), so the file that replaces another does not depend on the order of the
    /// filesystem.
    ///
    /// # Errors
    ///
    /// Returns the IO error from reading the directory, the parse error of a file prefixed with
    /// its path, or an error for a baseline whose name differs from the loaded baseline's name.
    pub fn with_dir(self, dir: &Path) -> Result<Set, String> {
        self.load_dir(dir, true)
    }

    /// Loads every module profile under `dir` (recursively) as [`Set::with_dir`] does, but only
    /// adds profiles and never replaces one. This loads the directories that keys.toml's
    /// `profileDirs` names at run time. A file there may add a new module profile, and with it a
    /// new family. It may not add a baseline, a layer profile or a hardware profile, and it may
    /// not use a name that is already loaded. The embedded profiles belong to this repository,
    /// and profiles/LEDGER.toml records the measurement of each one, so a file from outside the
    /// build must not silently replace one of them.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Set::with_dir`], and an error for a file that would replace a
    /// loaded profile or that is not a module profile.
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
                // The set uses only one baseline ([`Set::baseline`]). A baseline from a directory
                // replaces the loaded baseline of the same name (for example, a regenerated
                // pkcs11-3.2). A baseline of another name is refused, because it would otherwise
                // be loaded and never read.
                let b = Baseline::from_toml(&text).map_err(|e| at(&e))?;
                match &mut self.baseline {
                    Some(loaded) if loaded.baseline == b.baseline => *loaded = b,
                    loaded => {
                        return Err(at(&format!(
                            "baseline '{}': only one baseline is used ({}); a directory may replace it, not add another",
                            b.baseline,
                            loaded.as_ref().map_or("", |l| l.baseline.as_str())
                        )));
                    }
                }
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

    /// Returns the set against which every token open resolves. [`Set::activate`] or
    /// [`Set::activate_embedded`] builds it once per process (ISSUES.md Q24). This function never
    /// builds the set itself. As a result, an activation that comes too late causes an error at
    /// the place that first asked for the set, instead of silently producing a different set.
    ///
    /// # Errors
    ///
    /// Returns an error if no set has been activated yet.
    pub fn active() -> Result<&'static Set, String> {
        ACTIVE.get().ok_or_else(|| {
            "no capability profile set is active: the tool activates it (Set::activate) right after \
             reading keys.toml, before anything asks for a profile"
                .to_owned()
        })
    }

    /// Builds the active set: the embedded profiles plus every module profile under `dirs`
    /// ([`Set::adding_dir`]). A process calls this once, before it opens the first token.
    ///
    /// # Errors
    ///
    /// Returns the error of a file that loading refuses, or an error if a set is already active.
    pub fn activate(dirs: &[std::path::PathBuf]) -> Result<&'static Set, String> {
        Set::activate_replacing(dirs, None)
    }

    /// Does what [`Set::activate`] does, and then loads every profile under `replacing` over
    /// the result ([`Set::with_dir`]). This implements caprobe's `--profiles`, which measures
    /// profiles that are not yet committed.
    ///
    /// # Errors
    ///
    /// Returns the error of a file that loading refuses, or an error if a set is already active.
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

    /// Activates the embedded set, for a process that loads no profile directory (the tests and
    /// caprobe). If a set is already active, it returns that set, so a process may call it more
    /// than once.
    ///
    /// # Errors
    ///
    /// Returns the parse error of [`Set::embedded`].
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

    /// Returns the baseline: the embedded baseline, or the file of the same name with which a
    /// [`Set::with_dir`] directory replaced it. A directory cannot add a second baseline.
    ///
    /// # Errors
    ///
    /// Returns an error when no baseline was loaded.
    pub fn baseline(&self) -> Result<&Baseline, String> {
        self.baseline.as_ref().ok_or_else(|| "no baseline loaded".to_owned())
    }

    /// Returns every loaded profile, in load order. Resolution iterates over this list to match
    /// modules and forwarders by their `match` rows.
    #[must_use]
    pub fn all(&self) -> &[Profile] {
        &self.profiles
    }

    /// Returns the families of the module profiles (`mode = "observed"`) whose
    /// `[match] manufacturer` is `manufacturer`. This is how cakeys recognizes and names a module
    /// that no provider code claims, from data alone (docs/CAPROBE.md: a module that needs no
    /// fix-ups needs no Rust code). Layer profiles are never counted.
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

    /// Returns every loaded module profile family, sorted. A keys.toml `provider` may name one of
    /// these families in addition to the providers that have code.
    #[must_use]
    pub fn module_family_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> =
            self.profiles.iter().filter(|p| p.mode == Mode::Observed).map(Profile::family).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Returns the profile named `name`, by its exact name ("softhsm/2.7") or, when only one
    /// version of the family is loaded, by its family ("softhsm"). A keys.toml `provider` names a
    /// profile in one of these two ways.
    ///
    /// # Errors
    ///
    /// Returns an error that lists the loaded names when nothing matches. Returns an error that
    /// lists the matching versions when a family matches several versions, so that the user can
    /// name one exactly.
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

/// Collects every `.toml` file under `dir`, recursively. It follows symlinked directories (a Nix
/// `symlinkJoin` of profile directories consists of them), but it reads each real directory only
/// once. A link back to an ancestor, or a second link to a directory that was already read, adds
/// nothing, so a symlink loop ends and no file loads twice.
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
    // The entries are sorted, so the choice of which of two links to one directory is read does
    // not depend on the order of the filesystem.
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

    /// No set is active until a caller activates one (ISSUES.md Q24). A request for the set
    /// before activation is an error. It does not silently return the embedded set, because a
    /// later activation would then fail. The embedded activation may repeat, but a second
    /// activation with directories is refused. This is the only test in this binary that
    /// activates a set, because the active set is global to the test binary.
    #[test]
    fn the_set_is_activated_before_it_is_asked_for() {
        assert!(Set::active().err().unwrap().contains("no capability profile set is active"));
        let set = Set::activate_embedded().unwrap();
        assert!(std::ptr::eq(set, Set::active().unwrap()));
        assert!(std::ptr::eq(set, Set::activate_embedded().unwrap()), "the embedded activation repeats");
        assert!(Set::activate(&[]).err().unwrap().contains("already in use"));
    }

    /// The embedded set holds the committed profiles. This test checks that every file parses,
    /// that every name is unique, and that the answers on which other checks rely still hold.
    #[test]
    fn embedded_profiles_load_and_answer() {
        let set = Set::embedded().unwrap();
        assert!(set.baseline.is_some());
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
        // `find` by an exact name, by a unique family, by a family that has no profile, and by
        // an unknown name.
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
        // The profile that the probe verified holds the full `C_GetMechanismList`, so SHA-512
        // HMAC is decided as Yes. The earlier partial profile, written by hand, left it Unknown.
        assert!(matches!(eff.mechanism("CKM_SHA512_HMAC"), Verdict::Yes { .. }));
        assert_eq!(set.find("softhsm/2.7").unwrap().wrap_oaep().as_deref(), Some(["SHA-1".to_owned()].as_slice()));
        // A partial module profile (one that records no mechanism list) answers Unknown, and
        // never guesses.
        let partial = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\npartial = true\n").unwrap();
        let eff = Effective::new(b, Some(&partial), &[]);
        assert!(matches!(eff.mechanism("CKM_SHA512_HMAC"), Verdict::Unknown { .. }));

        // The cryptoki layer removes the SHA-512 HMAC key type, which an unpatched binding cannot
        // handle [run]. Whether this build's binding is patched is a check that crates/pkcs11
        // makes at run time.
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
        // The pair profile alone decides what the probe observed: the refused size and the
        // curves. A size that the probe never tried answers Unknown. It does not answer from the
        // range that the module reports.
        let pair = Effective::new(b, Some(tpm2), &[]);
        assert!(matches!(pair.generate("CKK_RSA", None, Some(4096)), Verdict::No { .. }));
        assert!(matches!(pair.generate("CKK_RSA", None, Some(2048)), Verdict::Yes { .. }));
        assert!(matches!(pair.generate("CKK_RSA", None, Some(8192)), Verdict::No { .. } | Verdict::Unknown { .. }));
        assert!(matches!(pair.curve("secp256k1"), Verdict::No { .. }));
    }

    /// If every probed row answers no, the query answers No. If the rows are absent, the
    /// capability was not probed, and the query answers Unknown. (A test in caprobe checks that
    /// the emitter keeps this difference.)
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

    /// The committed profiles name only rows that this version of cakeys knows (review D4). A
    /// profile from a newer cakeys loads even when it has names that this version does not know.
    /// A misspelled name in a committed profile would therefore also load, and it would answer
    /// nothing, so this test checks the names.
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

    /// A profile from a newer cakeys that names a proof, hashes and a template attribute that
    /// this version does not know still loads (ISSUES.md Q28, review D4). Those unknown rows
    /// answer nothing: each query of this version gets the same answer as it would without them.
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

    /// A misspelled key in any section is refused and never ignored. For example, a `[match]`
    /// section whose version key is misspelled would otherwise match by manufacturer alone.
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

    /// The loader follows a directory's symlinks to directories, and it reads each real directory
    /// once. A link to an ancestor does not loop forever (review lib.rs F1), and a second link to
    /// a directory that was already read does not load any file twice.
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
        // Loading the directory adds each profile once, so a second path to a profile does not
        // cause an "already loaded" error.
        let set = Set::embedded().unwrap().adding_dir(dir.path()).unwrap();
        assert!(set.find("m/1").is_ok() && set.find("n/1").is_ok());
    }

    /// A baseline from a directory replaces the loaded baseline of the same name, and queries
    /// then use it. A baseline of another name is refused, so it is never loaded and left unread
    /// (review lib.rs F2).
    #[test]
    fn a_directory_baseline_is_used_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("baseline.toml");
        let committed = embedded::BASELINE_FILES[0].1;
        let newer = committed.replacen("[mechanisms]\n", "[mechanisms]\nCKM_FROM_A_DIRECTORY = 0x80000001\n", 1);
        assert_ne!(newer, committed);
        std::fs::write(&file, &newer).unwrap();
        let set = Set::embedded().unwrap().with_dir(dir.path()).unwrap();
        assert!(set.baseline.is_some());
        assert!(set.baseline().unwrap().mechanisms.contains_key("CKM_FROM_A_DIRECTORY"));
        std::fs::write(&file, committed.replacen("baseline = \"pkcs11-3.2\"", "baseline = \"pkcs11-9.9\"", 1)).unwrap();
        let e = Set::embedded().unwrap().with_dir(dir.path()).err().unwrap();
        assert!(e.contains("baseline 'pkcs11-9.9': only one baseline is used (pkcs11-3.2)"), "{e}");
    }

    /// A `--profiles` directory is read recursively. A baseline replaces the embedded baseline,
    /// a profile with a loaded name replaces the loaded profile, a new profile is added, and a
    /// file that is neither a baseline nor a profile is refused with its name in the error.
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
        assert!(set.baseline.is_some(), "the baseline of its name is replaced");
        assert!(set.find("softhsm/2.7").unwrap().partial);
        assert_eq!(set.all().iter().filter(|p| p.profile == "softhsm/2.7").count(), 1);
        assert!(set.find("m").is_ok());
        std::fs::write(nested.join("odd.toml"), "name = \"x\"\n").unwrap();
        let e = Set::embedded().unwrap().with_dir(&dir).err().unwrap();
        assert!(e.contains("odd.toml: neither a baseline nor a profile"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// keys.toml's `profileDirs` only add module profiles. A new family loads. A file that
    /// replaces an embedded profile, or that holds a layer or a baseline, is refused.
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

    /// The verdict on a secret key's generation is decided by the lengths in bytes that the
    /// probe tried. For AES, only an exact match counts, because AES lengths are discrete. For a
    /// type whose length is free, a length between two lengths that generated also counts. A
    /// layer's `restrict` bounds are in bits, so the check multiplies a length by eight. A
    /// profile with no row answers Unknown, and never Yes from the mechanism alone.
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
        // 24 bytes lies between two lengths that generated, but AES lengths are discrete, so the
        // verdict is Unknown.
        assert!(matches!(verdict("CKK_AES", Some(24)), Verdict::Unknown { .. }));
        // No length is asked for, and at least one length generated.
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
        // Every length was refused, so the type answers No.
        let none = module("\"generate.CKK_SHA256_HMAC.16\" = { answer = \"no\" }\n");
        let eff = Effective::new(b, Some(&none), &[]);
        assert!(matches!(eff.generate_secret("CKK_SHA256_HMAC", None), Verdict::No { .. }));
        // A layer bounds a size in bits: 32 bytes is 256 bits, and 48 bytes is 384 bits.
        let layer =
            Profile::from_toml("profile = \"l/1\"\nmode = \"delta\"\n[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_AES\"\nmax-bits = 256\n")
                .unwrap();
        let layers = [&layer];
        let eff = Effective::new(b, Some(&aes), &layers);
        assert!(matches!(eff.generate_secret("CKK_AES", Some(32)), Verdict::Yes { .. }));
        assert!(matches!(eff.generate_secret("CKK_AES", Some(48)), Verdict::No { by, .. } if by == "l/1"));
    }

    /// Detection from data returns the families whose module profiles name a manufacturer.
    /// Layer profiles (p11-kit) never count.
    #[test]
    fn module_families_come_from_observed_profiles() {
        let set = Set::embedded().unwrap();
        assert_eq!(set.module_families("SoftHSM"), ["softhsm"]);
        assert_eq!(set.module_families("CloudHSM"), ["aws-cloudhsm"]);
        assert_eq!(set.module_families("PKCS#11 Kit"), Vec::<&str>::new());
        assert_eq!(set.module_families("Nobody"), Vec::<&str>::new());
    }
}
