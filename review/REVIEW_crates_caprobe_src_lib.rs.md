# Review: crates/caprobe/src/lib.rs (314 lines)

Reviewed 2026-11-18 [read]. Summary: the `caprobe` command line: clap definitions, `dispatch`
(optional keys.toml, profile activation, `--module`), and the `caps`, `supports` and `probe`
verbs, including writing a generated profile (`write_profile`) and the drift exit. Compact and
clear. The main issue is that `supports` and `probe --diff` look profiles up in a set built here
that leaves out keys.toml's `profileDirs`, contrary to CAPROBE.md.

## Findings

### F1. `supports --token` and `probe --diff` ignore keys.toml's `profileDirs` — bug

**Verification:** confirmed. `run_supports` (lib.rs:222) and `run_probe` (:254-256) build `profile_set` = `Set::embedded()` plus `--profiles` only (:206-217), never `Set::active()`, which `activate_profiles` built with `profileDirs` (cli-common/src/lib.rs:41-55); docs/CAPROBE.md:142 promises `profileDirs` for all three tools. [read]
`crates/caprobe/src/lib.rs:206-217`, `:222`, `:254-256`; `crates/caprobe/src/supports.rs:70-99`.
`dispatch` activates the process set with `activate_profiles(&cfg, notes)` (185), which adds
`profileDirs`; but `run_supports` and `run_probe` query a second set, `profile_set(--profiles)`
= `Set::embedded()` plus the `--profiles` directory only. CAPROBE.md: "keys.toml's
`profileDirs` add module profiles at run time for all three tools". Scenario: keys.toml has
`profileDirs = ["./vendor-profiles"]` holding `acme/1.0.toml` and `tokens.hsm.provider =
"acme"`; `caprobe --config keys.toml supports --token hsm CKM_ECDSA` fails with 17 "no profile
'acme' (loaded: …)", and `caprobe probe --token hsm --diff acme/1.0` fails the same way, while
`caprobe caps --token hsm` (which opens the token through the active set) resolves `acme/1.0`.
Fix: start `profile_set` from `Set::active()` (already activated by `dispatch`) and layer
`--profiles` over a clone of it, or pass `cfg.profile_dirs` through `adding_dir` before
`with_dir`. [read]

### F2. `main_from` exits the host process and works once per process — practice

`crates/caprobe/src/lib.rs:157-167`, `:175-183`; `crates/cli-common/src/lib.rs:42`.
`main_from` is documented as "caprobe run in-process by a binary or a test", but
`Cli::parse_from` and the missing-`--config` path (`.exit()`) call `process::exit` inside the
host, and a second call in the same process fails with 17: `activate_profiles` →
`Set::activate` refuses once the `OnceLock` is set ("the profile set is already in use").
`tests/template_hook.rs` calls it once, so the tests do not see it. Fix: `try_parse_from` and
return the clap error's exit code; document the one-call limit, or let `activate_profiles`
accept an already-active set built from the same directories. [read]

### F3. The probe's `--profiles` flag has no help text — nit

`crates/caprobe/src/lib.rs:135-136`.
`ProbeArgs::profiles_dir` has no doc comment (the `supports` one does, 112-114), so
`caprobe probe --help` lists `--profiles` without saying it is only the `--diff` lookup (it does
not change how the token is opened). [read]

## Design

- Two profile sets live in one run: `Set::active()` (embedded + `profileDirs`), which
  `Token::open` resolves against, and `profile_set(--profiles)`, which `supports` and `--diff`
  read (F1). `binding::layer()` reads the embedded layer only, so `--profiles` cannot replace the
  binding layer, which is why the unpatched model is a separately named
  `cryptoki/0.12-unpatched`. One set, with `--profiles` applied as the one documented exception
  ("adds or replaces entries"), would remove both surprises.
- `supports --token` re-implements a reduced token resolution (see the supports.rs review): it
  is not `gate::stack`, which `cakeys validate` uses for the same question.

## Checked, no issue

- B14 (Done): `write_profile` proceeds only when the file is absent (`NotFound`); any other read
  error refuses, so a file that might hold claims is never overwritten blind; `keep_claims` then
  refuses an unparsable file and a read-only probe over an existing one.
- `--diff` drift lines go to stderr, the profile to stdout, and drift exits 15 as documented.
- The probe opens the token `unprofiled()`, so the committed profile does not shape what is
  measured; `kept` (`--out` or `--diff`) is what the unpatched-binding refusal keys on.
- `supports --profile` runs with no keys.toml (`Config::default()`); every other verb requires
  `--config`, with a clap usage error.
- `profile_round_trip` (the fuzz entry point) checks parse → emit → parse and emit idempotence.
