# Review: crates/camigrate/src/plan.rs (852 lines)

Reviewed 2026-11-18 [read]. Summary: the pure migration planner. From the lock's type and policy
and each side's capabilities, it picks the strongest method and exposure (vendor, then sealed or
enforced, then host or file) and says why when nothing fits. Clean, small functions, and a test
for each fact it decides. One ordering question about vendor methods, and one lost explanation.

## Findings

### F1. A vendor method survives the target's `migration.refuses` block — risk

**Verification:** confirmed (downgraded to nit). The ordering is as described (plan.rs:133-149, best candidate taken at :180-181), but `Side::vendor` is only ever built as `vec![]` (core/src/migrate.rs:324) and nothing in pkcs11, profile or camigrate fills it, so no input reaches it; a latent ordering note for phase 7, not a risk today. [read]
`crates/camigrate/src/plan.rs:133-142` (vendor candidates offered first), `:144-149` (`refuses`
only adds a `blocked` reason). Then `:180-181` take the best candidate, so a vendor method still
wins. The reason text says the target "takes in no {type} by any import", yet the plan comes out
`ready` by a vendor method into that target. No in-tree provider declares vendor methods (phase
7), so this cannot be reached today. When one does, check `refuses` before offering anything, or
filter `ways.candidates` there. [read]

**Fixed (2026-11-18):** vendor methods are offered only in the arm of a target that does not
refuse the type, after the `refuses` check. Test: `vendor_methods_compete_at_their_declared_level`
(a vendor method into a refusing target is not ready and names `migration.refuses`).

### F2. A plan blocked only by `--allow-host-plaintext` hides why the sealed ways were refused — nit

`crates/camigrate/src/plan.rs:179-188`. When the best candidate is `host`/`file`, `blocked`
(why sealed or enforced was impossible: no shared OAEP hash, no RFC 5649, …) is dropped, and
the plan says only "the host path needs --allow-host-plaintext". Users then pass the flag
without learning that a fix on a profile or mechanism would have kept the key sealed. Add the
blocked reasons as notes on a host/file plan. [read]

**Fixed (2026-11-18):** a host or file plan carries each blocked reason as a "not sealed: …" note,
with or without the flag. Test: `a_host_plan_says_why_it_is_not_sealed`.

## Design

- The planner is pure and deterministic, but some rules about where a key lands live outside it
  (lib.rs `landing_checks`, `limit_*_plans`, `no_import_pair`) and run only on paths that plan.
  See the lib.rs review, F1/F2.

## Checked, no issue

- `OAEP_DIRECT_MAX = 190` is the SHA-256 bound under 2048 bits, conservative for SHA-1 (214), and
  `check_transport_size` keeps every transport key at 2048 bits or more.
- Exportability: `CKA_EXTRACTABLE != true` or `never_extractable` blocks before any method is
  considered (D1).
- `CKA_WRAP_WITH_TRUSTED`: never a host or file path. `enforced` needs `trusted_wrap` and a
  trusted copy, and the composed method then needs `CKM_RSA_AES_KEY_WRAP` on the source.
- The OAEP hash is the strongest both sides list. Since it is the same for every object of one
  invocation, `Bundle::parse`'s one-hash-per-KEK rule always holds for camigrate's own exports.
- Private data objects have no method between tokens.
