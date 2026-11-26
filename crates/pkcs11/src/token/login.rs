//! Logging in: the PIN guard, the session a token opens, and the SO steps (review 2026-11-23
//! B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// The PIN counters `C_GetTokenInfo` reports (M2): a login on the final try or a locked PIN is
/// refused before it is attempted, so a wrong PIN file never spends the last retry (PIV allows
/// few).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PinState {
    pub(super) user: Pin,
    pub(super) so: Pin,
}

/// One PIN's counters.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Pin {
    pub(super) locked: bool,
    pub(super) final_try: bool,
    /// A login failed since the last success, but retries remain: a warning, never a refusal.
    pub(super) count_low: bool,
}

impl Pin {
    /// Refuse a login as `who` (user or SO) the counters say must not be tried.
    fn guard(self, token: &str, who: &str) -> Result<()> {
        let Pin { locked, final_try, .. } = self;
        if locked {
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': the {who} PIN is locked (CKF_{}_PIN_LOCKED); unlock it with the vendor's tools",
                    who.to_uppercase()
                )
                .into(),
            ));
        }
        if final_try {
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': one {who} PIN try is left before it locks (CKF_{}_PIN_FINAL_TRY); cakeys will \
                 not spend it on a PIN file that may be wrong — log in once by hand with the right PIN to reset \
                 the counter",
                    who.to_uppercase()
                )
                .into(),
            ));
        }
        Ok(())
    }
}

impl Token {
    /// Run `step` in a Security Officer session (`soCredentialFile`/`soCredentialEnv`), for modules that
    /// create and destroy objects only as SO, then return to the user session. Login state is
    /// per token, so the user is logged out first. The admin credential is read here, never at
    /// open, and zeroized when the step ends. A step already in the SO session runs as it is:
    /// `Token::create` and the destroys enter it before the provider's override, which may ask
    /// again ([`Token::managing`]).
    ///
    /// # Errors
    ///
    /// `Unsupported` without an admin credential configured; `Unavailable` when the SO login,
    /// the logout or the return to the user session fails, or the PIN counters refuse a login;
    /// else whatever `step` returns.
    pub fn as_so<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        use std::sync::atomic::Ordering;
        if self.in_so.load(Ordering::Relaxed) {
            return step();
        }
        let so = read_so_credential(&self.name, &self.cfg)?.ok_or_else(|| {
            self.unsupported(format!(
                "{what} on '{}' needs a Security Officer session: set tokens.{}.soCredentialFile or soCredentialEnv",
                self.name, self.name
            ))
        })?;
        self.pins.so.guard(&self.name, "SO")?;
        if self.so_refused.load(Ordering::Relaxed) {
            return Err(KmError::Unavailable(
                format!(
                    "token '{}': the SO credential was refused earlier in this run; it is not tried again, \
                     which could spend the last retry",
                    self.name
                )
                .into(),
            ));
        }
        if self.logged_in {
            self.session.logout().map_err(ck("C_Logout"))?;
        }
        let out = match self.session.login(UserType::So, Some(&AuthPin::new(so.as_str().to_owned().into()))) {
            Ok(()) => {
                self.in_so.store(true, Ordering::Relaxed);
                let out = logged_in_as(&self.session, UserType::So, &self.name).and_then(|()| step());
                self.in_so.store(false, Ordering::Relaxed);
                let logout = self.session.logout().map_err(ck("C_Logout (SO)"));
                so_outcome(what, &self.name, out, logout)
            }
            Err(e) => Err({
                self.so_refused.store(true, Ordering::Relaxed);
                KmError::Unavailable(
                    format!(
                        "{SO_LOGIN} with soCredentialFile/soCredentialEnv: {rv}; it must hold the module's admin \
                 credential (the SO PIN; ykcs11: the PIV management key in hex, or the PIN on a \
                 device whose management key is PIN-protected)",
                        rv = rv_name(&e)
                    )
                    .into(),
                )
                .with_rv(rv_of(&e))
            }),
        };
        drop(so);
        if !self.logged_in {
            return out;
        }
        let back = match self.pin.as_deref() {
            None => Err(KmError::Unavailable("no user PIN to log back in with".into())),
            Some(pin) => match self.session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                    logged_in_as(&self.session, UserType::User, &self.name)
                }
                Err(e) => Err(KmError::Unavailable(format!("C_Login (back to the user): {}", rv_name(&e)).into())
                    .with_rv(rv_of(&e))),
            },
        };
        so_outcome(what, &self.name, out, back)
    }
}

/// Whether `session` shows the login `who` the module just accepted: a module that answers
/// `CKR_OK` to `C_Login` and leaves the session public hides every private object, so a search
/// would read a key it cannot see as absent (review 2026-11-24, lead-found through the Phase 2
/// design). `C_GetSessionInfo` says which it is.
///
/// # Errors
///
/// `Unavailable` (16) when the session is not in `who`'s state, or the state cannot be read.
pub(super) fn logged_in_as(session: &Session, who: UserType, token: &str) -> Result<()> {
    use cryptoki::session::SessionState;
    let state = session.get_session_info().map_err(ck("C_GetSessionInfo"))?.session_state();
    let shown = match who {
        UserType::So => state == SessionState::RwSecurityOfficer,
        _ => matches!(state, SessionState::RoUser | SessionState::RwUser),
    };
    if shown {
        return Ok(());
    }
    Err(KmError::Unavailable(
        format!(
            "token '{token}': C_Login ({who:?}) succeeded, but the session is not logged in (C_GetSessionInfo: \
             {state:?}): the module would hide every private object, so nothing it finds or misses is trusted"
        )
        .into(),
    ))
}

/// What [`Token::as_so`] answers once the session is put back (`after`: the SO logout, then the
/// user's login): the step's own result first. A step that failed is reported as it failed,
/// never as the session trouble after it; a step that succeeded and a session that could not be
/// restored is an error that says the step was done, so a caller never takes a key it made (or
/// a trusted copy) for one that was not.
pub(super) fn so_outcome<T>(what: &str, token: &str, step: Result<T>, after: Result<()>) -> Result<T> {
    match (step, after) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => {
            let rv = e.rv();
            Err(KmError::Unavailable(
                format!(
                    "{what} on '{token}' was done, but the session could not be restored afterwards ({e}): \
                     what it made or changed is on the token"
                )
                .into(),
            )
            .with_rv(rv))
        }
    }
}

/// Whether `access` opens a read-write session on token `name`, `write_protected` or not:
/// only to write, or for scratch objects where the token allows it. A write on a
/// write-protected token is refused (15), and so is its dry run, which opens read-only: it
/// refuses what its run refuses (review 2026-11-24 L4a-3).
fn read_write(access: Access, write_protected: bool, name: &str) -> Result<bool> {
    match access {
        Access::Write | Access::DryWrite if write_protected => Err(KmError::Unsupported(
            format!(
                "token '{name}' is write-protected (CKF_WRITE_PROTECTED): it can be read, never created on or \
                 deleted from"
            )
            .into(),
        )),
        Access::Write => Ok(true),
        Access::Scratch => Ok(!write_protected),
        Access::Read | Access::DryWrite => Ok(false),
    }
}

/// Open the session `access` asks for (M1, [`read_write`]) and log in as the user when a PIN is
/// configured — unless the counters say the login must not be tried (M2).
#[expect(clippy::too_many_arguments, reason = "the open's parts, as Token::open has them")]
pub(super) fn session(
    ctx: &Pkcs11,
    logins: &Logins,
    slot: cryptoki::slot::Slot,
    name: &str,
    cfg: &TokenCfg,
    access: Access,
    write_protected: bool,
    pins: PinState,
) -> Result<(Session, Option<Zeroizing<String>>)> {
    let session = if read_write(access, write_protected, name)? {
        ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?
    } else {
        ctx.open_ro_session(slot).map_err(ck("C_OpenSession (read-only)"))?
    };
    let pin = read_pin(name, cfg)?;
    if let Some(pin) = pin.as_deref() {
        pins.user.guard(name, "user")?;
        let mut logins = logins.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
            Ok(()) => {
                logins.insert(slot.id(), Zeroizing::new(pin.to_owned()));
            }
            // Kept only when this process logged in with the same PIN: the PIN is used again
            // where a wrong one costs (a PIV context login, the TPM unseal).
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _))
                if logins.get(&slot.id()).is_some_and(|p| p.as_str() == pin) => {}
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                return Err(KmError::Unavailable(
                    format!(
                        "token '{name}': already logged in by another session of this process with another PIN, so \
                         this token's PIN cannot be checked"
                    )
                    .into(),
                ));
            }
            Err(e) => return Err(KmError::Unavailable(format!("C_Login: {}", rv_name(&e)).into()).with_rv(rv_of(&e))),
        }
        logged_in_as(&session, UserType::User, name)?;
    }
    Ok((session, pin))
}

/// The user PIN (`pinEnv`, else `pinFile`, its `$NAME` resolved now).
pub(super) fn read_pin(name: &str, cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    // `pinEnv` wins: an unset `pinFile` variable is no error then.
    let file = if cfg.pin_env.is_some() { None } else { cfg.pin_path(name, &|var| std::env::var(var).ok())? };
    cakeys_core::secret::read("PIN", cfg.pin_env.as_deref(), file.as_deref())
}

/// Whether keys.toml gives the token an admin (Security Officer) credential, which [`Token::as_so`]
/// reads.
#[must_use]
pub fn has_admin(cfg: &TokenCfg) -> bool {
    cfg.so_credential_file.is_some() || cfg.so_credential_env.is_some()
}

/// The admin credential (`soCredentialEnv`, else `soCredentialFile`), read only for an SO step. The format
/// is the module's: ykcs11 takes the PIV management key in hex, or the PIN on devices whose
/// management key is PIN-protected.
pub(super) fn read_so_credential(name: &str, cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    let file = if cfg.so_credential_env.is_some() {
        None
    } else {
        cfg.so_credential_path(name, &|var| std::env::var(var).ok())?
    };
    cakeys_core::secret::read("SO credential", cfg.so_credential_env.as_deref(), file.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every access, on a token write-protected or not: a dry run of a write refuses exactly
    /// what the write refuses (15), and never opens read-write; only a write and scratch work
    /// open read-write, scratch never on a write-protected token; a read refuses nothing (review
    /// 2026-11-24 L4a-3: `create --dry-run` and `delete --dry-run` passed a write-protected
    /// token).
    #[test]
    fn a_dry_run_refuses_the_token_its_write_refuses() {
        for access in [Access::Read, Access::Write, Access::Scratch, Access::DryWrite] {
            let writes = match access {
                Access::Write | Access::DryWrite => true,
                Access::Read | Access::Scratch => false,
            };
            for protected in [false, true] {
                let got = read_write(access, protected, "t").map_err(|e| e.exit_code());
                let want = match access {
                    _ if writes && protected => Err(15),
                    Access::Write => Ok(true),
                    Access::Scratch => Ok(!protected),
                    Access::Read | Access::DryWrite => Ok(false),
                };
                assert_eq!(got, want, "{access:?}, write-protected {protected}");
            }
        }
        for protected in [false, true] {
            assert_eq!(
                read_write(Access::DryWrite, protected, "t").is_err(),
                read_write(Access::Write, protected, "t").is_err(),
                "write-protected {protected}"
            );
        }
    }

    /// `as_so` reports the step first (token/mod.rs F2): a step that succeeded is never dropped
    /// for a failed logout or re-login without saying it was done, and a step that failed is
    /// never hidden behind the session trouble after it.
    #[test]
    fn the_so_step_is_reported_before_the_session_trouble() {
        let trouble = || Err(KmError::Unavailable("C_Logout (SO): CKR_DEVICE_ERROR".into()));
        assert_eq!(so_outcome("generating a key", "piv", Ok(7), Ok(())).unwrap(), 7);
        let done = so_outcome("generating a key", "piv", Ok(7), trouble()).unwrap_err();
        assert!(
            matches!(&done, KmError::Unavailable(m) if m.contains("generating a key on 'piv' was done")
                && m.contains("CKR_DEVICE_ERROR")),
            "{done}"
        );
        let failed =
            so_outcome::<()>("generating a key", "piv", Err(KmError::Unsupported("refused".into())), trouble());
        assert!(matches!(failed, Err(KmError::Unsupported(m)) if *m == *"refused"));
    }
}
