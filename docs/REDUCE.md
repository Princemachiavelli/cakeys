# Reducing the code base: crates that could replace hand-written code (2026-11-13, at 05ab213)

Short answer: crates can't shrink this code base much. Most of the size is domain logic that has
no crate equivalent: the lock rules, capability profiles, the probe and the migration planner. The
research in `reports/` reached the same conclusion for the lock design ("no surveyed system
combines…").

There are a few places, though, where the code re-implements something a dependency it already
has, or a standard crate, does better. This is a survey only; nothing was changed.

## Re-implementations worth replacing

| Where | What's hand-written | Replace with | Gain |
|---|---|---|---|
| `crates/tpm2-pkcs11/src/attest/esys.rs:298`, `:361` | `unsafe` `Tss2_MU_*` FFI calls to unmarshal `TPM2B_PUBLIC` and marshal `TPMS_ATTEST` | tss-esapi 7.7, already a dependency: `PublicBuffer::unmarshall` / `Public::unmarshall` and `Attest::marshall` (`tss_esapi::traits`) call the same functions | Two of the workspace's three `unsafe` exemptions go away; about 40 lines |
| `crates/ykcs11/src/attest.rs:104-175` | A DER TLV walker (handles lengths only up to `0x82`) to get the TBS and signature bytes, and a PEM splitter | x509-cert's `pem` feature (`Certificate::load_pem_chain`; `pem-rfc7468` is already in the lock file), `cert.signature().raw_bytes()`, and a `#[derive(Sequence)]` struct holding the TBS as `AnyRef` for its exact original bytes | About 70 lines, and certificate parsing stays in one audited parser |
| Five hex decoders: `token/uri.rs:56`, `probe.rs:207`, `attest/store.rs:282`, `ykcs11/src/lib.rs:155`, tests in `id.rs` | Slightly different rules each time (`probe.rs` silently drops bad pairs) | `base16ct`, already in the lock file via RustCrypto, or `hex` | One behaviour everywhere |
| `crates/tpm2-pkcs11/src/attest/store.rs:230` | Line-based parsing of tpm2-pkcs11's libyaml output (`? !!int "258"`, skipping sequences by looking for `]`) | A real YAML parser, e.g. `serde_norway` (`serde_yaml` is archived) | More robustness than line savings, but it costs a dependency |
| `crates/core/src/config.rs:897` (`save_lock`) | Temp file, fsync, rename | `tempfile::NamedTempFile::persist` or `atomic-write-file` | Adds the directory fsync that's currently missing, and a unique temp name |
| `crates/core/src/config.rs:950` (`access(2)`) | `unsafe` libc call | `rustix::fs::access` | Removes the third `unsafe` exemption except the loader lookup in `crates/pkcs11/src/token/mod.rs` |

Hand-written code to keep:

- **The `ESYS_TR` parsing in `store.rs:192`.** tss-esapi has a comment saying
  `Esys_TR_Deserialize` is missing.
- **`seal_auth` and the objauth unwrap.** They mirror tpm2-pkcs11's own protocol, which no crate
  implements.
- **The PKCS#11 header parser in `baseline.rs`.** cryptoki-sys gives constants, not a list of
  names you can iterate.
- **RFC 7512 URI building.** It's 40 lines. `percent-encoding` would only replace `pct`.

The hand-written TOML emitter in `profile.rs` (about 150 lines, kept so generated profiles survive
`nix fmt` byte for byte) could become `toml` serialization plus the `taplo` library formatting it
at the repo's 120-column setting. That's a heavy dependency to save 150 lines, so leave it unless
the emitter keeps growing.

## For the lock-file spec

Nothing generic exists for the rules themselves: write-only-adds, never-weaken and required
realisations. `reconcile.rs` is the right place for them. Three crates would help with defining
the format:

1. **`serde_jcs` (RFC 8785, JSON Canonicalization Scheme)** for `spec_digest`. `canonical_json`
   in `id.rs:49` is our own canonical form, and DESIGN.md §10 describes it informally. Naming
   RFC 8785 lets another language recompute a spec digest from a standard rather than from the
   code, which is what `CONTRACT.md` is after. For the current inputs (booleans, integers, ASCII
   keys), JCS output should be byte-identical, so `spec_digests_are_pinned` would confirm no
   digest changes. If one does change, it goes into the planned v2 bump.
2. **`schemars`** to generate JSON Schemas for `keys.toml` and `keys.lock` from the serde types.
   That would give:
   - The published, versioned schema `CONTRACT.md` lists under "To decide" #2.
   - Editor validation, since taplo validates TOML against a JSON Schema (`#:schema` directive).
   - A machine-readable spec for other-language readers.

   Cross-field invariants (`check_objects`, `check_pairs`) stay in code.
3. **Keeping unknown provenance keys on rewrite.** The review requires preserving them (the TUF
   re-serialization rule), but `deny_unknown_fields` plus typed structs drops them when the lock
   is rewritten. No crate is needed: a `#[serde(flatten)] extra: BTreeMap<String, toml::Value>`
   on the provenance table fixes it. Use `toml_edit` only if comments and order should also
   survive.

On signing the lock, still an open question: when it is decided, reuse an existing format rather
than designing one. Options include SSH signatures (`ssh-key`'s `SshSig`), minisign, or
sigstore/DSSE. If rollback protection matters, `tough` (TUF) already models the "versions only
move forward" property the lock rules enforce locally.

## Where the size actually is

By `docs/ARCHITECTURE.md` §3, capability profiles are about 21% of the Rust and the migration
planner about 10%. The planner covers export and import, which have no execution path yet; only
plans and `--dry-run` exist. Review A4 already notes the profile machinery is larger than its
current consumers need. If the goal is a smaller code base, deferring parts of those two would
remove far more than every crate swap above combined, which comes to roughly 250–300 lines.

Of the swaps, the tss-esapi one is the clear first pick. It's an existing dependency, removes
`unsafe`, and the swtpm integration tests already cover it.
