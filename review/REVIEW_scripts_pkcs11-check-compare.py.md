# Review: scripts/pkcs11-check-compare.py (105 lines)

Reviewed 2026-11-18 [read]. Summary: turns a pkcs11-check run's artifacts into Markdown beside a
caprobe profile: outcome counts, listed vs. advertised mechanisms, subtracted mechanisms still
invoked, failures and skips grouped by file and normalised reason. Straightforward.

## Findings

### F1. Arguments unchecked — nit

`scripts/pkcs11-check-compare.py:59`. A missing argument is an `IndexError` traceback; a usage
line would do. Only called from scripts/pkcs11-check.sh, which always passes both. [read]

**Fixed (2026-11-18):** usage line on a wrong argument count.

## Design

None.

## Checked, no issue

- Missing artifacts degrade to empty sections, so a partial run still summarises.
- Reasons are normalised (bracketed parameters, numbers) before grouping, and `|` is escaped for
  the Markdown table.
- `profile.get("add")` is a list of names in every committed profile, so `sorted` is safe.
