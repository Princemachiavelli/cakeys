//! The questions that only caprobe asks of an open token: the mechanisms that the token
//! advertises and their limits, the claims of `C_GetTokenInfo`, and a token opened without its
//! profiles (review 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// Returns the token in the form in which a probe measures it. No module profile decides
    /// anything here: neither its rows nor what it subtracts from or adds to the mechanism list.
    /// So every operation asks the module itself, and an operation whose answer the profile
    /// would have given is tried on the module instead. The layers between cakeys and the module
    /// stay, because they are not part of the module.
    ///
    /// # Errors
    ///
    /// `Validation` when the active profile set has no baseline.
    pub fn unprofiled(mut self) -> Result<Token> {
        self.profiles.module = None;
        self.mechanisms = usable_mechanisms(&self.listed, &self.profiles)?;
        // Add the mechanisms that the provider runs in its own way although the module does not
        // list them. The verbs get them through the profile's `add` list, which the probe
        // records, so the probe's proofs try them too (AWS CloudHSM's Ed25519 [run]).
        for m in self.provider.stand_ins() {
            if !self.mechanisms.contains(&m) {
                self.mechanisms.push(m);
            }
        }
        Ok(self)
    }

    /// Returns the usable mechanisms by their `CKM_*` names.
    pub fn mechanism_names(&self) -> Vec<String> {
        sorted_names(&self.mechanisms)
    }

    /// Returns what `C_GetMechanismList` returned, by name and sorted, with repetitions kept. The
    /// probe records this list as a profile's `advertise` list, which is the baseline for drift
    /// detection (D2).
    #[must_use]
    pub fn advertised(&self) -> Vec<String> {
        sorted_names(&self.listed)
    }

    /// Returns whether `C_GetMechanismList` listed `m`, regardless of what the profiles subtract.
    #[must_use]
    pub fn lists(&self, m: MechanismType) -> bool {
        self.listed.contains(&m)
    }

    /// Returns what `C_GetMechanismInfo` reports for `m`: the key-size range (in bits for RSA and
    /// EC, and in bytes for the symmetric mechanisms, as the module counts them) and the names of
    /// the operations that it flags. This is only a claim of the module, and it is never treated
    /// as evidence.
    #[must_use]
    pub fn mechanism_info(&self, m: MechanismType) -> Option<(usize, usize, Vec<&'static str>)> {
        let i = self.library.0.get_mechanism_info(self.slot, m).ok()?;
        let flags = [
            ("hardware", i.hardware()),
            ("encrypt", i.encrypt()),
            ("decrypt", i.decrypt()),
            ("sign", i.sign()),
            ("verify", i.verify()),
            ("generate", i.generate()),
            ("generate-key-pair", i.generate_key_pair()),
            ("wrap", i.wrap()),
            ("unwrap", i.unwrap()),
            ("derive", i.derive()),
        ];
        Some((i.min_key_size(), i.max_key_size(), flags.into_iter().filter(|(_, on)| *on).map(|(n, _)| n).collect()))
    }

    /// Returns [`Self::mechanism_info`] for every mechanism that the module lists, by name, with
    /// each mechanism once.
    #[must_use]
    pub fn mechanism_infos(&self) -> Vec<(String, usize, usize, Vec<&'static str>)> {
        let mut seen = std::collections::BTreeSet::new();
        self.listed
            .iter()
            .filter(|m| seen.insert(m.to_string()))
            .filter_map(|m| self.mechanism_info(*m).map(|(min, max, flags)| (m.to_string(), min, max, flags)))
            .collect()
    }

    /// Returns what `C_GetTokenInfo` reports about the token's state and limits, as
    /// `name -> value` claims (`[claims]` in a profile): the flags that are set, and the session
    /// and PIN limits.
    #[must_use]
    pub fn token_claims(&self) -> Vec<(String, String)> {
        let Ok(t) = self.library.0.get_token_info(self.slot) else { return Vec::new() };
        let flags = [
            ("write-protected", t.write_protected()),
            ("rng", t.rng()),
            ("login-required", t.login_required()),
            ("clock-on-token", t.clock_on_token()),
            ("protected-authentication-path", t.protected_authentication_path()),
            ("dual-crypto-operations", t.dual_crypto_operations()),
            ("token-initialized", t.token_initialized()),
            ("so-pin-count-low", t.so_pin_count_low()),
            ("so-pin-final-try", t.so_pin_final_try()),
            ("error-state", t.error_state()),
        ];
        let set: Vec<&str> = flags.into_iter().filter(|(_, on)| *on).map(|(n, _)| n).collect();
        vec![
            ("token.flags".into(), set.join(", ")),
            ("token.max-sessions".into(), limit(t.max_session_count())),
            ("token.max-rw-sessions".into(), limit(t.max_rw_session_count())),
            ("token.pin-length".into(), format!("{}-{}", t.min_pin_length(), t.max_pin_length())),
        ]
    }
}

/// Returns a session limit in the form in which a profile's `[claims]` write it. The text is
/// spelled here, and it never comes from cryptoki's `Debug` output, so that an update of the
/// binding cannot change committed profiles (review 2026-11-23 B-14).
pub(super) fn limit(l: cryptoki::slot::Limit) -> String {
    match l {
        cryptoki::slot::Limit::Max(n) => n.to_string(),
        cryptoki::slot::Limit::Unavailable => "unavailable".into(),
        cryptoki::slot::Limit::Infinite => "infinite".into(),
    }
}
