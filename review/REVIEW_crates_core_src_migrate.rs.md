# Review: crates/core/src/migrate.rs (450 lines)

Reviewed 2026-11-18 [read]. Summary: the frozen vocabulary of moves (exposure levels, method
names) and the data model of one side's move capabilities (`Accept`, `Probed`, `Side`). Plain
data with pinned names and a round-trip test; no logic beyond `Accept::covers`. No real issues.

## Findings

### F1. `Method::from_name` builds every built-in name to look one up — nit

`crates/core/src/migrate.rs:93-126`. `name()` returns a `String` (allocated even for constants)
because two variants are formatted, and `from_name` calls it for each of the 16 built-ins.
Called once per realisation at lock load (`check_realisations`). Negligible cost; a
`&'static str` table for the built-ins with formatting only for the parameterised variants
would also make the frozen names greppable in one place. [read]

**Fixed (2026-11-18):** a private `builtin_name` returns `&'static str` for every built-in, the
OAEP ones included, in one table; `name()` formats only the vendor variant, and `from_name`
compares against the table without allocating. Test: `method_names_are_pinned_and_round_trip`.

### F2. A vendor method name may contain `/` and anything else — nit

`crates/core/src/migrate.rs:120-124`. `vendor:<provider>/<name>` splits on the first `/` and
takes the rest as the name, so `vendor:luna/a/b` is provider `luna`, name `a/b`, and either
part may hold spaces or `.`. It round-trips, so nothing breaks; but these names are frozen
into locks, and `check_names`' grammar (`config.rs:1590`) would keep them uniform. [read]

**Fixed (2026-11-18):** both parts of `vendor:<provider>/<name>` must be keys.toml names
(`config::is_name`, the grammar `check_names` uses), so `vendor:luna/a/b`, a space, a `.` or a
leading `-` is an unknown method. Test: `names_print_and_half_named_vendor_methods_are_unknown`.

## Design

- `OaepHash` is imported from `pop` (`:8`): the frozen transport names depend on the proof
  module. See REVIEW pop.rs, Design.

## Checked, no issue

- Method and exposure names pinned and round-tripping (`method_names_are_pinned_and_round_trip`);
  half-named vendor methods refused.
- `Accept::covers`: a constraint the row names excludes an object that lacks the field
  (curve, modulus size), tested; `value_len` matches exactly.
- `Exposure` ordering (`PartialOrd`) follows declaration order, strongest first, as documented.
- Stale-comment fix from ISSUES.md ("the removed `migration` hook") holds: no reference left.
