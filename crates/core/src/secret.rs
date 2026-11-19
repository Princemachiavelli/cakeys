//! Secrets from the environment or a file: the one reader of the PIN, the SO credential and
//! camigrate's key-file passphrases (review D8: camigrate read the first line of a file and
//! exited 1 or 17 where the PIN's reader took the whole file and exited 16).

use crate::{KmError, Result};
use std::path::Path;
use zeroize::Zeroizing;

/// `what` from the environment variable `var`, else the file `path`: the file's text without
/// its trailing line endings. Neither configured is `None`.
///
/// # Errors
///
/// `Unavailable` (16) when the variable is not set or the file cannot be read; `Validation`
/// (17) when the variable is not UTF-8, when the file resolves into the world-readable Nix store
/// (unless `CAKEYS_ALLOW_NIX_STORE_KEYS=1`, `config::ALLOW_NIX_STORE_KEYS`), or when it holds
/// more than one line, which no secret does: rather than guess which line is meant, cakeys
/// refuses it.
pub fn read(what: &str, var: Option<&str>, path: Option<&Path>) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = var {
        return from_var(what, var, std::env::var(var)).map(Some);
    }
    let Some(path) = path else { return Ok(None) };
    // Checked where it is read, the link resolved now: keys.toml's load saw the path, not
    // whatever it points at by the time a run reads it.
    if let Some(why) = crate::config::secret_in_store(&format_args!("{what} file"), path) {
        return Err(KmError::Validation(why.into()));
    }
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| KmError::Unavailable(format!("{what} file {}: {e}", path.display()).into()))?,
    );
    let line = text.trim_end_matches(['\n', '\r']);
    if line.contains(['\n', '\r']) {
        return Err(KmError::Validation(format!("{what} file {} holds more than one line", path.display()).into()));
    }
    Ok(Some(Zeroizing::new(line.to_owned())))
}

/// `what` as the environment variable `var` holds it (`value`, what `std::env::var` read): an
/// unset one is unavailable, one that is set but not UTF-8 is invalid, never "not set".
fn from_var(what: &str, var: &str, value: Result<String, std::env::VarError>) -> Result<Zeroizing<String>> {
    match value {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(std::env::VarError::NotPresent) => {
            Err(KmError::Unavailable(format!("{what} env var {var} not set").into()))
        }
        Err(std::env::VarError::NotUnicode(raw)) => {
            // The bytes are the secret: wiped, never shown.
            drop(Zeroizing::new(raw.into_encoded_bytes()));
            Err(KmError::Validation(format!("{what} env var {var} is set but not UTF-8").into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A variable that is set but not UTF-8 is said to be so (17), never "not set" (16), and its
    /// bytes are not shown (review token/mod.rs F6).
    #[test]
    fn a_non_utf8_variable_is_not_unset() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(vec![b'1', 0xff, b'2']);
        let e = from_var("PIN", "V", Err(std::env::VarError::NotUnicode(raw))).unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("V is set but not UTF-8")), "{e}");
        let e = from_var("PIN", "V", Err(std::env::VarError::NotPresent)).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("V not set")), "{e}");
        assert_eq!(from_var("PIN", "V", Ok("1234".into())).unwrap().as_str(), "1234");
    }

    /// No secret is read from the world-readable Nix store, also through a link into it: refused
    /// (17) before the file is opened, whether it exists or not (review config.rs F4).
    #[test]
    fn a_secret_in_the_nix_store_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("result");
        std::os::unix::fs::symlink("/nix/store", &link).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        for path in [Path::new("/nix/store/x-pin"), &link.join("x-pin"), &dir.path().join("sub/../result/x")] {
            let e = read("PIN", None, Some(path)).unwrap_err();
            assert!(matches!(&e, KmError::Validation(m) if m.contains("PIN file") && m.contains("Nix store")), "{e}");
        }
        // Outside it, the file is read as before.
        let pin = dir.path().join("pin");
        std::fs::write(&pin, "1234\n").unwrap();
        assert_eq!(read("PIN", None, Some(&pin)).unwrap().as_deref().map(String::as_str), Some("1234"));
    }

    #[test]
    fn a_secret_is_one_line_of_its_file() {
        let dir = std::env::temp_dir().join(format!("cakeys-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |name: &str, text: &str| {
            let p = dir.join(name);
            std::fs::write(&p, text).unwrap();
            p
        };
        let read_file = |p: &Path| read("PIN", None, Some(p));
        for (text, want) in [("1234", "1234"), ("1234\n", "1234"), ("1234\r\n", "1234"), ("1234\n\n", "1234"), ("", "")]
        {
            assert_eq!(read_file(&file("ok", text)).unwrap().as_deref().map(String::as_str), Some(want), "{text:?}");
        }
        // A second line is refused, never read past or taken in.
        for text in ["1234\n5678\n", "1234\r5678", "\n1234"] {
            let err = read_file(&file("two", text)).unwrap_err();
            assert!(matches!(err, KmError::Validation(_)) && err.to_string().contains("more than one line"), "{err}");
        }
        assert!(matches!(read_file(&dir.join("absent")), Err(KmError::Unavailable(_))));
        assert!(matches!(
            read("PIN", Some("CAKEYS_TEST_SURELY_UNSET_VARIABLE"), Some(&dir.join("absent"))),
            Err(KmError::Unavailable(_))
        ));
        assert!(read("PIN", None, None).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
