# Review: examples/every-object/run.sh (67 lines)

Reviewed 2026-11-18 [read]. Summary: plays examples/every-object/keys.toml on SoftHSM, kryoptic
and swtpm: create, file imports, migration plans (expected 15 as a whole), per-object migrations,
then `check` on every token. Clear.

## Findings

### F1. The object lists are repeated from keys.toml — nit

`examples/every-object/run.sh:48`, `:54`. The migration loops name the objects by hand. An object
added to keys.toml is created and checked but not migrated, and the plan's expected 15 (some
objects stay) would not notice. Derive the lists from the dry run's JSON, or add a comment that
the loops must follow keys.toml. [read]

**Fixed (2026-11-18):** the loops take the dry run JSON's ready objects and require them to equal the written lists. Test: examples/every-object/run.sh passes locally.

## Design

None.

## Checked, no issue

- Every step's exit code is stated; `--allow-host-plaintext` is passed exactly where the method
  goes through the host.
