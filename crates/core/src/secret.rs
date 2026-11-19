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
/// (17) when the file holds more than one line, which no secret does: rather than guess which
/// line is meant, cakeys refuses it.
pub fn read(what: &str, var: Option<&str>, path: Option<&Path>) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = var {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("{what} env var {var} not set").into()));
    }
    let Some(path) = path else { return Ok(None) };
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

#[cfg(test)]
mod tests {
    use super::*;

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
