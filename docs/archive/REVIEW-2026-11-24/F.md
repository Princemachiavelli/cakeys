# Area F: history and process — review 2026-11-24

Reviewer F answers: what about this codebase's design, tests and process keeps generating issues
and lets them survive five whole-repo reviews in two weeks. Evidence is counts from git history
and the review markdown. Scripts are inline so the numbers can be reproduced.

## 0. Method and added codes

Sources parsed by script (`/tmp/cakeys-F/scripts/extract.py`, reproducible from the repo):
REVIEW-2026-11-11 (table rows), -13 (A-table), -15 (`### X1.` headings), ISSUES.md 2026-11-16
(B/Q items, including those only in its first version at 2120ec1), the 213 files of `review/`
at `61b7000^` (`### Fn. … — severity`, with the `**Verification:**` re-grade applied), and
REVIEW-2026-11-23/{A,B,C,D}.md. 631 prior findings in all.

Classification. 265 findings were classified by hand from title and body: every finding of
11-11, -13, -15, -16 and -23, and the 54 bug/risk findings of 11-18 that survived verification.
The other 366 (11-18 practice, complexity and nit) got a keyword classifier. **That classifier
agrees with the manual primary code on only 52% (137/265) of the hand-classified set**, so every
headline number below uses the manual set; the all-findings table is given for completeness.

Codes added to criteria.md (each needed for at least 13 findings):

| Code | Meaning |
|---|---|
| D-FAILOPEN | An error, an absence, an unread or unrecorded field, or "any failure" is mapped to a definite verdict (yes, no, ok, a default, a retry) instead of being an error or "unknown". |
| D-LIFECYCLE | Ordering, cleanup, rollback, durability or secret-wiping of an irreversible step (token write, lock save, process kill) on a failure path. |
| D-SPECULATIVE | Code, seam, option or crate built before a user; dead or single-user API; a module holding several concerns. |
| D-SURFACE | CLI surface defined per verb: flags, exit codes, help text, aliases disagree between verbs or tools. |
| D-LOCAL | A local logic slip (wrong field, bytes for bits, wrong encoding) with no structural cause beyond "no test". |
| P-CI | CI or build configuration: what is built, on which runner or system, with what bounds. |

## 1. Inventory and classification of prior findings

### 1.1 Counts per review

| Review | Findings | Severity mix | Evidence the review produced |
|---|---:|---|---|
| 2026-11-11 | 44 | 3 H, 16 M, 19 L, 6 D | "code reading" for most; a few reproduced |
| 2026-11-13 | 11 | 1 H, 5 M, 5 L | "code reading throughout; nothing reproduced" |
| 2026-11-15 | 18 | 7 [run], 11 [read] | the only prior review that ran anything (`[run]` = 7) |
| 2026-11-16 ISSUES.md | 46 | 19 B, 27 Q | "[read] unless it says otherwise"; plain `cargo test` only, "no Nix check was run" |
| 2026-11-18 review/ | 420 | 13 bug, 41 risk, 89 practice, 33 complexity, 242 nit, 2 withdrawn (after re-grade) | `[read]`; plain `cargo test` 532 passed, "token suites skip … no Nix check or token run" |
| 2026-11-23 | 92 | 1 critical, 2 high, 30 medium, 59 low | read-only by rule: "do not run cargo/nix builds or tests" |
| **Total** | **631** | | |

### 1.2 Recurrence: class × review (manual set, n = 265; multi-label, so columns sum to more than n)

| class | 11-11 | 11-13 | 11-15 | 11-16 | 11-18 bug/risk | 11-23 | total | reviews with ≥1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| findings (n) | 44 | 11 | 18 | 46 | 54 | 92 | 265 | |
| **D-FAILOPEN** | 15 | 1 | 1 | 4 | 10 | 18 | **49** | **6/6** |
| D-PARALLEL | 1 | 3 | 2 | 7 | 4 | 14 | 31 | 6/6 |
| D-LOCAL | 10 | 0 | 1 | 9 | 5 | 6 | 31 | 5/6 |
| D-TYPES | 6 | 0 | 6 | 9 | 3 | 4 | 28 | 5/6 |
| D-LIFECYCLE | 2 | 0 | 0 | 6 | 9 | 7 | 24 | 4/6 |
| T-GATED | 3 | 0 | 0 | 3 | 13 | 4 | 23 | 4/6 |
| D-SPECULATIVE | 0 | 3 | 1 | 7 | 0 | 12 | 23 | 4/6 |
| **D-MULTIPATH** | 2 | 2 | 3 | 2 | 7 | 6 | 22 | **6/6** |
| T-FRIENDLY | 6 | 1 | 0 | 3 | 2 | 8 | 20 | 5/6 |
| D-DOCS | 1 | 3 | 1 | 0 | 0 | 15 | 20 | 4/6 |
| D-SURFACE | 2 | 0 | 3 | 1 | 1 | 8 | 15 | 5/6 |
| **D-SEAM** | 1 | 1 | 2 | 1 | 4 | 5 | 14 | **6/6** |
| T-ORACLE | 1 | 0 | 0 | 0 | 3 | 4 | 8 | 3/6 |
| P-CI | 2 | 0 | 0 | 0 | 4 | 1 | 7 | 3/6 |
| T-INSTANCE | 0 | 0 | 0 | 0 | 1 | 1 | 2 | 2/6 |
| T-TAUTO | 0 | 0 | 0 | 0 | 1 | 1 | 2 | 2/6 |
| P-UNRUN | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 1/6 |

Read: **D-FAILOPEN, D-MULTIPATH, D-PARALLEL and D-SEAM appear in all six reviews.** D-FAILOPEN is
the largest class (49/265 = 18%) and is the largest in 11-11 and 11-23 alike: two weeks of
fixes did not reduce it. D-DOCS and D-SPECULATIVE jump in 11-23 because that review's criteria
asked for them ("Complexity reduction (high priority)", "doc-vs-code drift").

The T-* column is thin for prior reviews **because no prior review asked why a test missed the
finding**; only today's criteria do. Every prior finding escaped every test by definition (it
was found by reading), so the T-* counts are lower bounds.

All 631 (366 by the 52%-agreement classifier, so indicative only): D-LOCAL 218, T-ABSENT 141,
D-FAILOPEN 76, D-PARALLEL 68, D-SURFACE 63, D-LIFECYCLE 59, T-ORACLE 55, T-GATED 44, D-TYPES 44,
D-DOCS 43, D-MULTIPATH 34, D-SPECULATIVE 33, T-FRIENDLY 22, D-SEAM 17, P-CI 7.

### 1.3 Where classes recur (area × class present in ≥ 4 of 6 reviews, all findings)

| area | class | reviews | findings |
|---|---|---:|---:|
| core | D-FAILOPEN | 6 | 18 |
| core | T-ABSENT | 5 | 31 |
| core | D-SURFACE (exit codes) | 5 | 9 |
| pkcs11 | D-FAILOPEN | 4 | 13 |
| pkcs11 | D-TYPES | 4 | 6 |
| camigrate | D-PARALLEL | 4 | 15 |
| cli | D-PARALLEL | 4 | 15 |
| nix-ci | D-PARALLEL | 4 | 8 |
| tpm2-pkcs11 | T-FRIENDLY | 4 | 6 |

Also in 3 reviews: caprobe D-FAILOPEN (14), profile D-FAILOPEN (7), tpm2-pkcs11 D-FAILOPEN (7),
camigrate D-LIFECYCLE (13), caprobe/pkcs11/ykcs11 T-GATED (8/8/4), core D-MULTIPATH (6).

### 1.4 Sibling chains: the same defect class in the same place, review after review

Each row is one class found, "fixed" at the reported instance, and found again nearby.

| # | Class | 11-11 / -13 / -15 | 11-16 | 11-18 | 11-23 | 11-24 (today) |
|---|---|---|---|---|---|---|
| 1 | D-MULTIPATH: a write-guarding rule on one path | S4, L4, A7, A11, V5, N2 | B15, Q12 | camigrate lib F1, F2, F3; caprobe lib F1, supports F1; policy F1; config F1; **REVIEW_DESIGN D1 names the class** | B-3, C-2, A-2, A-10, A-12, C-23 | B-1, B-2 (B-3 fix on two paths), D-2, D-3, D-4, D-6, A-7, B-10 |
| 2 | D-FAILOPEN: "retry after any failure" | — | B18 (by-name retry) | — | B-8 (prove_ecdh) | B-6 ("survives prior B-8 in the by-name retry") |
| 3 | D-FAILOPEN: answer from absence in profile verdicts | — | B13 | effective F1, F2 | A-1, D-2..D-5, D-12, D-13 | A-9 ("mirror of 11-23 A-1, left in place") |
| 4 | D-FAILOPEN: a check that trusts what the module asserts | H1, H1b, S2, A8 | — | esys F1, sealed F1 | B-1, B-2, B-13, D-2, D-3 | B-12 (lying module/interposer untested) |
| 5 | Profile set resolved per tool | P1 | B15 | caprobe lib F1, supports F1 ("Left: … does not consult the lock") | — | B-7, B-10 |
| 6 | Module identity by spelling | — | B5 | token/mod F3 ("still keys a bare name apart") | — | (A-5: object identity by locator spelling) |
| 7 | RSA size arithmetic | — | B17 | — | C-20 (bytes not bits, camigrate) | B-5 ("C-20 fixed in camigrate only") |
| 8 | Secret wiping | — | B16 ("Done" claim false, corrected) | pop.rs F1, plaintext.rs F1 | C-22 | — |
| 9 | Transport-key binding | — | — | camigrate lib F3 | C-1 (high) | D-1 (C-1 fix binds to the file's own token), D-8, D-10 |
| 10 | Attestation chain rules | — | B8 (validity) | — | A-3 (critical ext., EKU) | A-7 (A-3 rules inside `chain_to_anchor` only) |
| 11 | PIV slot / scratch guard | — | — | camigrate lib F2 | D-1 (critical) | A-2, A-3 (label-only locator bypasses D-1) |
| 12 | ykcs11 auto-detection | — | — | ykcs11 lib F1 | — | B-10 ("fixed in code only") |
| 13 | Shipped build ≠ tested build | D6 | — | flake F1, examples F1 | C-8 | C-10 |
| 14 | Skips that pass | — | — | ftpm F1, dry_run F1, tpm2 F3, DESIGN D9 | — | C-7, C-11 |
| 15 | Test oracle weaker than claimed | L9 | ("Refusals asserted by code or message alone", "lock model's replay saw less") | xref F1, check F1, lockfile F1 | A-16, D-21, D-23 | A-6, A-10, C-5, C-8, C-9 |
| 16 | Docs assert removed behaviour | L7, A1, A10 | — | "Documentation drift found on the way" (8 items) | A-15, B-19..21, C-3, C-18, D-9, D-24 | A-1, A-2, C-2, C-13 |
| 17 | Lock save / partial-run reporting | M3 | B9 | camigrate lib F4, cli lib F1 | C-7, C-21, A-17 | C-1, D-9 |

17 chains; 16 of them reach 11-23 or today. Chain 1 is the clearest: the 2026-11-18 review named
the class ("Rules that guard irreversible writes live in planners, not at the write site") and
recommended the class fix ("put each rule … in the function that performs the write, and have
the planner call that same predicate"); its fix was applied to the reported instances, and 11-23
found 6 more and today's B and D find 8 more.

## 2. Fix-commit audit

41 prior findings marked fixed, 15 from 11-11..11-16, 11 from 11-18 and 15 from 11-23, across
core, pkcs11, profile, camigrate, caprobe, ykcs11, tpm2-pkcs11, the test harness and Nix. The fix
commits were found with `git log --grep`/`-S` over `/tmp/cakeys-F/messages.txt`. The tests each
commit added or removed were listed with `scripts/addedtests.sh <commit>`, which reads the `#[test]`
fns in the diff. (c) comes from reading the test against the fix. "gated" means the test fails
only when a token, swtpm or VM suite runs (§4). (e) is coded: **R** = the fix was wrong or its
test was later lost; **I** = instance only: the same rule was later found missing at another path
or site; **S** = a sibling of the same class in the same area; **N** = none found.

| # | Prior ID | Area | Fix commit | (a) test | (b) target | (c) fails if reverted | (d) unrun | (e) later |
|---:|---|---|---|---|---|---|---|---|
| 1 | 11-11 L1 non-ASCII `CKA_ID` panic | pkcs11 | 0feabc9 | `hex_decode_rejects_non_hex_without_panicking` | instance | yes | — | N |
| 2 | 11-11 M2 last PIN try spent | pkcs11 | 0ea445e | **none** | — | — | — | S: 11-18 yubikey.rs F1, 11-23 B-11 |
| 3 | 11-11 H1b `CKA_PUBLIC_KEY_INFO` trusted | pkcs11 | d0e5a60 (known-gap test first), a5f4cfb | `h1b_a_forged_public_key_info_is_a_conflict` | instance (SoftHSM RSA) | yes, red first; gated | — | S: 11-18 esys F1; 11-23 B-1, B-2; today B-12 |
| 4 | 11-11 S4 `publicOnly` flip only under `--update-lock` | core | d0e5a60, fix | `s4_a_public_only_flip_is_a_spec_change` | instance | yes, red first; gated | — | S: 11-13 A2 (lock write skips the same compares) |
| 5 | 11-11 L6 delete removes every public key | pkcs11 | e0aee60 | `delete_removes_only_what_it_identified` (later renamed) | instance | yes; gated | — | S: today B-4, B-13 (delete) |
| 6 | 11-13 A2 silent re-record | core | 05ab213 | `a_write_says_what_it_rerecorded` | instance | yes | — | S: 11-18 reconcile F1; 11-23 A-2; today A-5 |
| 7 | 11-15 C2/N3 name grammar, shell quoting | core, nix | e1fc47e | `names_are_letters_digits_dashes_and_underscores` | instance | yes, **until 8aaba2e deleted it** | — | **R**: test lost (today A-1) |
| 8 | 11-15 V3 exit 10 means two things | core | 39815bc | asserts changed (3 files) | instance | yes | — | S: 11-18 cli-common F1; 11-23 A-11, A-14, A-17, C-12 |
| 9 | 11-15 C1 two specs create one object | core | 03aebe6 | `create_refuses_births_…` (gone same day, 0c18d09) | instance | yes | — | S: 11-23 A-2; today A-5 |
| 10 | 11-16 B5 library cache by spelling | pkcs11 | 2120ec1 | **none** ("no test of its own") | — | — | flake check "did not run" | **I**: 11-18 token/mod F3 "still keys a bare name apart" |
| 11 | 11-16 B15 `supports --token` resolution | caprobe | 2120ec1 | **none** | — | — | same | S: 11-18 caprobe lib F1, supports F1 (bugs); today B-7, B-10 |
| 12 | 11-16 B16 secrets wiped | core | 2120ec1 | **none** ("a wipe is not observable") | — | — | same | **R**: "Done" claim false (11-18); 11-23 C-22 |
| 13 | 11-16 B17 RSA size, leading zeros | pkcs11 | 2120ec1 | **none** | — | — | same | **I**: 11-23 C-20; today B-5 (Token::check still counts bytes) |
| 14 | 11-16 B18 by-name retry after any failure | pkcs11 | b72e1f6 | `a_refused_curve_is_tried_by_name_only_where_the_profile_says_so` | instance (Edwards) | yes; gated (fault shim) | — | **I**: 11-18 correction; 11-23 B-8; today B-6 "survives" |
| 15 | 11-16 B8 chain validity dates | ykcs11, core | 6351f06 | unit `check_holds_the_chain_to_its_dates` + CLI test | instance | unit yes; **CLI test no** (11-18 check.rs F1: never reaches an attestation) | "Not run on the YubiKey" | S: 11-23 A-3; today A-7 |
| 16 | 11-18 camigrate lib F1/F2 attestation guard bypassed | camigrate | dc3f102 | `an_import_the_provider_cannot_attest_…`, `landing_checks_follow_the_spec_named` | code class (every import), test one path | yes; gated | red first claimed | S: 11-23 B-3; today B-1, B-2, D-2 |
| 17 | 11-18 policy F1 certificate policy unchecked | pkcs11 | dc3f102 | `a_certificates_declared_attributes_are_checked` | instance | yes; gated | red first claimed | S: today C-6 (no lie reaches a certificate), B-8 |
| 18 | 11-18 config F1 gc writes an unloadable lock | core | dc3f102 | `gc_and_save_leave_a_lock_that_loads` | **class** (save validates any lock) | yes | red first claimed | S: 11-23 A-4, A-17 (save_lock) |
| 19 | 11-18 config F2 first module hash only | core | dc3f102 | case in `locks_that_contradict_themselves_are_invalid` | instance | yes | red first claimed | N |
| 20 | 11-18 effective F1 all-no answers yes | profile | dc3f102 | `refused_rows_never_add_up_to_yes`; `answers.txt` regenerated (had pinned the wrong answer) | instance | yes | red first claimed | **I**: 11-23 A-1; today A-9 |
| 21 | 11-18 esys F1 ReadPublic not the attested blob | tpm2-pkcs11 | dc3f102 | `the_material_is_the_attested_blobs_not_read_publics` | instance | yes | red first claimed | S: 11-23 B-1 (high), B-2; today B-12 |
| 22 | 11-18 ptool F1 `--id` hex vs text | tpm2-pkcs11 | dc3f102 | unit + `tpm2_ptool_imports_under_the_locator_id` | instance | yes; half gated | red first claimed | **I**: "Left: camigrate's dry run does not refuse such an ID" (at fix time); today D-3 |
| 23 | 11-18 ykcs11 lib F1 claims YubiHSM 2 | ykcs11 | ab58460 | `only_the_piv_module_is_ykcs11` (unit of `matches`) | instance | yes | red first claimed | **I**: today B-10 (still auto-detects through the profile family) |
| 24 | 11-18 caprobe lib F1 / supports F1 profile set | caprobe | dc3f102, 1fb908c | cases in `supports_asks_by_token_…`; "probe --diff … untested" | instance | supports yes; `--diff` no | red first claimed | **I**: today B-7, B-10 |
| 25 | 11-18 ftpm F1 opted-in suite passes empty | harness | ab58460, 9e5b7bf | `no_opted_in_suite_skips_an_unpatched_build` + one `opted_in` helper | **class** | yes | WIP "not gated", gated in 9e5b7bf | **I**: today C-7 (4 opt-ins bypass it), C-11 |
| 26 | 11-18 emit F1 dropped fields | caprobe | ab58460 | `every_optional_field_alone_round_trips` (hand-kept list) | instance | yes | red first claimed | **I**: 11-23 D-20 (list drifted); today E "instance only" |
| 27 | 11-23 A-1 yes from absence | profile | fce5432 | `secret_lengths_interpolate_only_between_two_that_worked` | instance (yes half) | yes | **unbuilt** ("Not built or tested here"); core tests did not compile until fcaa6aa | **I**: today A-9 (no from absence, same fn) |
| 28 | 11-23 A-2 weaker record by a second spec | core | fce5432 | `a_second_spec_of_the_same_object_cannot_record_it_weaker` | instance | yes | **unbuilt** | **R**: today A-5 (bypassed by locator spelling; over-refuses) |
| 29 | 11-23 A-3 chain walker extensions | core | fce5432 | `issuers_sign_certificates_and_critical_extensions_are_understood` + fixtures | instance (`chain_to_anchor`) | yes | **unbuilt**; fixtures unparsable until fcaa6aa | **I**: today A-7 (PIV slot link bare) |
| 30 | 11-23 B-1 tpm-certify of a secret key | tpm2-pkcs11 | 6900764 | `tpm2_a_secret_keys_attestation_is_bound_to_its_material` + unit | instance (store path) | yes; gated (swtpm) | **"Not built or run here"** | **I**: today B.md: vendor path's refusal untested (B-12) |
| 31 | 11-23 B-3 PIV-slot rule in `create` override only | ykcs11, pkcs11 | fce5432 | validate.rs gate cases | instance (gate, `check_import`) | yes; gated | **unbuilt** | **I**: today B-1, B-2, D-2 |
| 32 | 11-23 C-1 transport file names any pinned key | camigrate | fce5432 | `a_transport_file_of_another_pinned_key_is_refused` | instance (same token, other object) | yes; gated | **unbuilt** | **I**: today D-1 (another target's genuine file passes), D-8 |
| 33 | 11-23 C-2 `migrate --dry-run --spec` | camigrate | fce5432 | dry_run.rs `--spec` cases | instance (`--spec`) | yes; gated | **unbuilt** | S: today D-2, D-3, D-4, D-6 (other rules the dry run skips) |
| 34 | 11-23 C-13 ptool writes before identity | camigrate | fcaa6aa | **none** | — | — | — | **I**: today D-5 (`export_file`, secret keys unchecked) |
| 35 | 11-23 C-16 missing `--lock` read as empty | cli, core | 6d4beab | VM test asserts 17 | instance | yes; gated (VM) | merged with CI red | **R**: today C-3 (two Nix checks now exit 17; red at HEAD) |
| 36 | 11-23 C-20 modulus bits vs bytes | camigrate | fcaa6aa | `a_modulus_counts_its_bits` (camigrate unit) | instance | yes | — | **I**: today B-5 (pkcs11 `Token::check` counts bytes) |
| 37 | 11-23 D-1 scratch-slot guard (critical) | caprobe | fce5432 | reference.rs placeholder-only case | instance | yes; gated | **unbuilt** | **I**: today A-3 (label-only locator loads), E-6 |
| 38 | 11-23 D-2 signatures counted unverified | caprobe | fce5432 | `only_a_verified_signature_adds_a_mechanism` | instance (`add` rows) | yes | **unbuilt** | **I**: today E-4 (4 mechanisms still unchecked) |
| 39 | 11-23 A-10 proof forbidden by allowed list | core | fcaa6aa | unit + `the_proofs_mechanisms_are_the_ones_load_checks` (table parity) | **class** (5 of 9 key kinds) | yes | — | N |
| 40 | 11-23 A-4/A-12 lock mode, sidecar | core | fce5432 | `a_saved_lock_keeps_its_mode_and_a_read_only_sidecar_guards` | instance | yes | **unbuilt** | N |
| 41 | 11-23 C-14 empty `passphraseEnv` (itself 11-18 F6's sibling) | camigrate | fcaa6aa | `an_empty_passphrase_is_refused_by_its_source` | **class** (every source) | yes | — | N |

### 2.1 Rates (n = 41)

| Measure | All | 11-11..16 (15) | 11-18 (11) | 11-23 (15) |
|---|---:|---:|---:|---:|
| (a) fix added or changed a test | 35/41 = **85%** | 10/15 = 67% | 11/11 = 100% | 14/15 = 93% |
| (b) that test covers the class, not the instance | 4/35 = **11%** | 0/10 | 2/11 | 2/14 |
| (c) test fails if the fix is reverted | 34/35 = 97% (row 15's CLI half: no; row 7: no longer, test deleted) | | | |
| (c′) …but only when a token/swtpm/VM suite runs | 13/35 = **37%** | | | |
| (d) fix landed unbuilt ("not built or run here") or merged with CI red | 11/41 = **27%** | 0 | 0 (its WIP checkpoints were gated before merge) | 11/15 = **73%** |
| (e) later review found R or I (same rule, same place) | 22/41 = **54%** | 5/15 | 6/11 | 11/15 |
| (e) later review found R, I or S | 36/41 = **88%** | 14/15 | 10/11 | 12/15 |

What this shows:

- **A test per fix did not stop recurrence.** The 11-18 round is the control case: every fix had a
  test, each claimed to have been checked red by restoring the old code ("Every fix has a test
  that fails with the old code restored", ab58460). Even so, 10 of 11 have a later
  sibling, and 6 of 11 are instance-only. The tests were right, but too narrow: they pin the
  reported input, not the rule.
- **The 11-23 round dropped the build step.** fce5432 (9 of the 15 audited 11-23 fixes) says
  "Not built or tested here: nix flake check decides", and 6900764 (B-1, high) says "Not built
  or run here". The next commit, fcaa6aa, lists "core tests that did not compile (a closure
  lifetime), chain-rules fixtures with explicit EC parameters". That gate was already red and
  stayed red through the merge (lead-verified CI, §4).
- **Tests can be lost silently.** 8aaba2e ("Both moves are verbatim", Co-Authored-By Claude
  Haiku 5.5) removed 8 `#[test]` fns from `core/src/config/mod.rs`:
  `names_are_letters_digits_dashes_and_underscores`, `no_secret_file_is_in_the_nix_store`,
  `env_references_and_object_refs_are_checked_at_load`, `paths_resolve_before_they_compare`,
  `unknown_classes_and_key_types_are_invalid_at_load`,
  `origins_say_how_an_object_comes_to_be_on_a_token`, `des3_value_len_is_the_key_types` and
  `objects_born_in_files_read_their_migrate_file`. None exists at HEAD
  (`git grep "fn <name>"` = 0), and DESIGN.md and FILE.md still cite three of them. No gate
  counts tests, so a net loss of 8 tests was invisible. 61b7000 also shows +38/−35 test fns.

## 3. Velocity and churn

Scripts: `churn.py` (over `git log --numstat`), `snap.py` (`git archive` of each review's
commit), `density.py`, `blame.py`, `baseline_blame.py`.

### 3.1 Commits and lines per day

The repository is 14 calendar days old. It has 461 commits on 11 active days (none on 11-20 to
11-22). Over its history, 181,946 lines were added and 64,788 deleted. Commit types are
classified from the subject line, heuristically.

| day | commits | fix | feature | refactor | test | +src .rs | +tests/ .rs | +docs | net src | net tests/ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 11-11 | 46 | 13 | 22 | 6 | 2 | 4,741 | 3,163 | 5,180 | 4,164 | 2,842 |
| 11-12 | 80 | 6 | 25 | 11 | 5 | 10,764 | 4,494 | 2,792 | 6,659 | 1,934 |
| 11-13 | 58 | 5 | 28 | 11 | 3 | 11,984 | 3,404 | 3,214 | 7,707 | 2,081 |
| 11-14 | 72 | 14 | 18 | 6 | 16 | 6,282 | 3,349 | 3,441 | 5,108 | 3,220 |
| 11-15 | 90 | 32 | 15 | 1 | 20 | 6,813 | 4,565 | 1,718 | 4,583 | 2,385 |
| 11-16 | 7 | 1 | 5 | 0 | 1 | 3,797 | 383 | 927 | 2,741 | 365 |
| 11-17 | 32 | 3 | 20 | 5 | 4 | 4,947 | 4,163 | 455 | 2,571 | 502 |
| 11-18 | 35 | 23 | 7 | 0 | 2 | 9,530 | 4,589 | 11,009 | 5,812 | 2,975 |
| 11-19 | 31 | 4 | 11 | 2 | 7 | 4,179 | 522 | 1,168 | 3,387 | 505 |
| 11-23 | 5 | 3 | 1 | 0 | 0 | 1,705 | 348 | 2,035 | 1,314 | 320 |
| 11-24 | 5 | 2 | 0 | 0 | 0 | 7,095 | 1,294 | 358 | 444 | 282 |
| **total** | **461** | 106 | 152 | 42 | 60 | 71,837 | 30,274 | 32,297 | 44,490 | 17,411 |

The pace is 42 commits and about 16,500 added lines (22,400 added plus deleted) per active day, peaking at 90 commits on
11-15. A further 46 commits are review docs and 55 are CHECKPOINT or merge commits. The 11-23
round's fixes were five commits of 56 to 348 files each: fce5432 (58 files, +1,658), fcaa6aa (56),
6d4beab (114, +2,151/−1,448) and 61b7000 (348, +4,865/−15,620). A batch that size cannot be
reverted one finding at a time, and it was not built (§2).

### 3.2 Features against fixes between reviews

| window | commits | fix | feature | refactor | test | +src | +tests/ | net src | net tests/ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| before the 11-11 review | 14 | 5 | 6 | 1 | 2 | 2,689 | 2,022 | 2,424 | 1,862 |
| 11-11 → 11-13 | 134 | 17 | 49 | 18 | 6 | 16,151 | 6,521 | 10,596 | 3,356 |
| 11-13 → 11-15 | 134 | 17 | 45 | 15 | 29 | 16,315 | 6,383 | 11,742 | 5,337 |
| 11-15 → 11-16 | 65 | 31 | 8 | 1 | 10 | 5,429 | 4,049 | 3,459 | 1,907 |
| 11-16 → 11-18 | 43 | 5 | 27 | 5 | 6 | 9,068 | 5,059 | 5,523 | 1,366 |
| 11-18 → 11-23 | 61 | 26 | 16 | 2 | 7 | 13,385 | 4,598 | 8,988 | 2,981 |
| 11-23 → 11-24 | 10 | 5 | 1 | 0 | 0 | 8,800 | 1,642 | 1,758 | 602 |

Lines per crate at each review's commit:

| crate | 11-13 (6b91684) | 11-15 (95258f9) | 11-18 (69ee620) | 11-24 (bc94263) |
|---|---:|---:|---:|---:|
| core | 4,858 | 6,627 | 8,681 | 10,893 |
| pkcs11 | 3,959 | 4,900 | 7,218 | 8,940 |
| cli | 5,742 | 7,829 | 9,131 | 11,122 |
| camigrate | 0 | 6,757 | 8,691 | 10,679 |
| caprobe | 0 | 3,912 | 5,205 | 8,175 |
| p11-fault | 0 | 2,491 | 1,638 | 2,156 |
| tpm2-pkcs11 | 1,267 | 1,721 | 1,845 | 3,594 |
| kmsp11 + aws-cloudhsm | 0 | 664 | 679 | 758 |

The 11-13 review found that "about 40% of the code serves features beside 'pin and verify' …
built before the lock format and the consumer contract are settled" (A4, A5). In the two days
after it, camigrate (6.8k lines), caprobe (3.9k), p11-fault (2.5k) and two cloud providers were
written. Every window after a review adds more source than the fixes touch. The review/fix loop
runs on a surface that grows 10–30% per window.

### 3.3 Is the code growing faster than its tests?

| review | src lines (no inline tests) | inline test lines | tests/ + fuzz lines | `#[test]` fns | test:src lines |
|---|---:|---:|---:|---:|---:|
| 11-11 | 2,246 | 178 | 1,862 | 41 | 0.91 |
| 11-13 | 11,158 | 1,793 | 5,217 | 160 | 0.63 |
| 11-15 | 21,301 | 4,615 | 11,317 | 336 | 0.75 |
| 11-16 | 23,168 | 4,984 | 12,464 | 358 | 0.75 |
| 11-18 | 27,692 | 5,983 | 13,830 | 396 | 0.72 |
| 11-23 | 33,382 | 9,316 | 16,807 | 580 | 0.78 |
| 11-24 | 34,945 | 9,511 | 17,409 | 598 | 0.77 |

**By lines, no:** test code has kept a steady 0.72–0.78 of source since 11-15. **By what
actually runs and asserts, yes.**

- Most integration tests need a token suite that runs only in the Linux crane check phase. The
  dev gate is darwin, where tpm2 is not compiled and the VM checks do not exist (C.md, Test
  execution matrix; §4).
- The only mutation run on record (COVERAGE_PLAN, 2026-11-15) missed 162 of 605 viable mutants
  in core (27%) and 22 of 85 in profile (26%) before tests were written against the lists.
  `packages.mutants` covers core, profile and four camigrate modules. It does not cover pkcs11,
  cli, caprobe or the providers, which hold most of today's findings. It runs weekly and gates
  nothing.

### 3.4 Do findings cluster in churn, or in review-fix code?

Over 164 `.rs` files (module stems) that exist at HEAD:

- **Prior findings cluster in churn.** The top churn quartile (41 files) holds 199 of 399
  file-attributed prior findings (50%). Normalised by size (142 files of 50 lines or more,
  ranked by churn per line), the top quartile has **10.4 prior findings/KLOC against 1.8** in
  the bottom quartile (5.8×). Spearman ρ is 0.56 for churn/line against findings/KLOC. The raw
  ρ of 0.71 is confounded by size, since size and churn correlate at ρ = 0.82.
- **Today's findings do not cluster in churn.** They are flat across churn quartiles: 1.03, 0.50,
  0.49 and 1.06 per KLOC. Their density is highest in files written in one go by review-fix
  commits. `camigrate/src/landing.rs` (448 lines, touched once, by the 11-23 fixes) has 3;
  `pkcs11/src/registry.rs` (189 lines, touched once) has 2.
- **Review-fix code is where today's findings are.**
  - 80 of 461 commits (17%) are review-fix commits: they cite a review or a finding ID. They
    changed 35% of all lines in history.
  - At HEAD, **45% of the 61,710 lines of `crates/**/*.rs` were last written by a review-fix
    commit** (`git blame`).
  - Of the lines today's findings cite, 58% were (same method; 48% with `-M -C` move tracking).
    That is 1.3× the base rate.
  - 46 of the 53 blameable findings (87%) cite at least one line last changed by a review-fix
    commit, and 24 (45%) cite mostly such lines.
  - The commits most often under today's cited lines are 61b7000 (21 findings), 4221b07 ("WIP
    checkpoint … not gated", 13), 6d4beab (12) and fce5432 (unbuilt, 11).

## 4. Validation pipeline as practiced

### 4.1 The documented gate against the gate in practice

DEVELOPMENT.md sets three steps. Per change: clippy and "the unit tests". After a significant
change: `nix build .#checks-crane-only`. At the end of a piece of work: `nix flake check`, "all
checks passing". CI (`checks.yml`) runs on pushes to `main` and on PRs, x86_64-linux only.

What happened:

- **CI runs after the push.** Of 461 commits, 435 have one parent. Three pull requests were
  merged (#3 on 11-15, #4 on 11-18, #5 on 11-24); the other merges are local worktree merges,
  and everything else was pushed to `main` and checked afterwards. Nothing in
  the tree requires CI before a merge (branch protection is not visible from here).
- **CI has been red since 11-19** (lead-verified from the GitHub API):
  - The `checks` workflow has run 23 times on pushes to main; 12 were green.
  - It was red on every main push since 38967ae (2026-11-19): 38967ae, 01583c8, 4304989 and
    bc94263. The last green run was 78a25ad (11-19 23:00).
  - At HEAD both jobs fail: `light` (`.#checks-no-vm`) and `vm` (`.#checks-vm`). C.md C-3
    identifies the failing `checks.profiles` and `checks.examples` by reading.
- **The 11-23 review began on a red main** (its commit 4304989 is red) **and its fixes landed
  red:**
  - fce5432 says "Not built or tested here: nix flake check decides".
  - 6900764 (B-1, high) says "Not built or run here".
  - fcaa6aa then fixed "the last round's gate failures: clippy …, core tests that did not
    compile".
  - PR #5's `checks` runs on 61b7000 and 8aaba2e were red, and it was merged (bc94263).
  - The `reports` workflow stayed green throughout. It never gates.
- **Commit messages rarely say what was run.**
  - Of 406 commits that are not CHECKPOINT or merge commits, 56 (14%) claim something ran
    ("passes", "clippy … clean", "checks-crane-only passes").
  - 19 state that something was not run or built. 340 (84%) say nothing.
  - One (9e5b7bf) claims the full gate (`.#checks-no-vm` and `.#checks-vm`).
  - Six say "The full flake check … did not run", and five say a hardware or cloud path was
    "not run" or "not yet run" on the device.
  - The 11-18 fixes were committed as three "WIP checkpoint … (not gated)" commits
    (4221b07, 46a6f66, 9d45634), with the line "unbuilt as a whole: the full suite, crane and
    the VM checks have not run on it". They were gated in 9e5b7bf. That checkpoint is the
    second most common commit under the lines today's findings cite (13 findings).
- **The deciding gate is not the gate the work is written against.** The dev machine is darwin,
  and its `checks-crane-only` does not compile tpm2. The VM, examples, fuzz and Kani checks do
  not exist there. The fast token run and profile regeneration are Linux-only (C.md C-12 and
  root cause 1). CI is Linux-only, and no runner builds darwin.

### 4.2 How much of the suite needs tokens or hardware, and when it runs

From C.md's test execution matrix (counts of tests per suite):

| Tier | Tests | Runs in plain `cargo test` / darwin? | Runs before merge? |
|---|---:|---|---|
| Token suites: SoftHSM and kryoptic reference suites (75 each), fault (14+7+6), p11-kit, references, caprobe reference, camigrate dry_run (25), pkcs11 library/logins/templates | about 245 | **skip and pass** under cargo; run in the crane check phase | only if the author ran crane; CI runs after the push |
| TPM (swtpm): cli tpm2 (21), caprobe tpm2 (2) | 23 | not compiled on darwin; the binaries vanish unnoticed | CI after the push |
| Hardware: ftpm (5), yubikey (5), cloud (2) | 12 | skip and pass; the cloud suite has no require variable | **never automated** |
| Token-free integration (core refusals, properties, harness, surface, from_files, …) | about 63 | run | yes, if the author runs cargo |
| Inline `#[cfg(test)]` units | about 352 `#[test]` fns | run | yes, if the author runs cargo |

- About 280 of roughly 340 integration-test executions (82%) need a token, swtpm or hardware.
  These are the tests that exercise PKCS#11 behaviour, lying modules and moves. Under the
  per-change step DEVELOPMENT.md names, all of them skip and pass.
- In the fix audit (§2), 13 of 35 regression tests (37%) are in this tier.
- Every prior review that ran anything ran plain `cargo test`:
  - ISSUES.md: "the token suites skip under plain `cargo test`, and no Nix check was run".
  - review/ INDEX: "Token suites skip under plain `cargo test` … no Nix check or token run".
  - 11-23 and today: nothing is run, by rule.

### 4.3 Mutation, coverage, skip-count and test-count gates

| Gate | Exists? | Gates merge? |
|---|---|---|
| Coverage (`packages.coverage`, llvm-cov) | yes: a badge on each push to main | **no**: "a failure leaves the badge stale and gates nothing" (C.md) |
| Mutation (`packages.mutants`, cargo-mutants) | yes: weekly; core, profile, 4 camigrate modules | **no**. pkcs11, cli, caprobe and the providers are out of scope |
| Skip count or zero-skip | partial: `*_REQUIRE` variables turn some skips into failures in crane | **no count**: "No runner counts the tests that ran" (C.md root cause 5). The fault suites' guard is set in the same `case` arm it guards (C-11), and four opt-ins bypass the helper (C-7) |
| Test count, or no net test deletion | **none** | 8aaba2e deleted 8 tests and nothing noticed |
| Revert check (does the new test fail without the fix?) | done by hand once, in the 11-18 round ("checked by putting the old code back") | not repeated in 11-23 |
| Hostile-module matrix (verb × object class × lie) | partial: the p11-fault lie table covers 3 verbs × private keys | no (C-6) |

## 5. The review process itself

### 5.1 What each review was asked to do, and did

| Review | Stated scope and method | Not read, or not done | What its criteria asked for |
|---|---|---|---|
| 11-11 | all crates, Nix, harness; "code reading" for most findings, a few reproduced | — | H/M/L/D severity; a recommendation per finding |
| 11-13 | "the design as a whole … not a line-by-line bug hunt"; "nothing here was reproduced" | line-level code | architecture, threat model |
| 11-15 | verbs, Nix library, config, profiles; 7 `[run]` findings | — | architecture; the only prior review with a verification run, and it found the per-change check red on main (E1) |
| 11-16 ISSUES.md | every `src/` file; plain `cargo test` ("token suites skip … no Nix check was run") | **integration test bodies (~13k lines)**, `caprobe/baseline.rs`, `p11-fault/names.rs`, most of `nix/`, `scripts/` | bugs, poor practice |
| 11-18 review/ | 211 files, one agent per batch, then a verification pass that re-read the 85 bug/risk findings | fixtures, profiles, docs, patches; "practice, complexity and nit findings were not separately verified" | bug/risk/practice/complexity/nit; a `## Design` section |
| 11-23 | whole repo; "do not run cargo/nix builds or tests" | nothing run | 8 categories, with "4. Complexity reduction (**high priority**)"; test quality is one clause of category 7 |
| 11-24 (today) | whole repo, read-only, nothing run | nothing run | **first** to require mental mutation testing, an entry-point audit and "why missed" codes |

Authorship (lead-verified): of the commits' Co-Authored-By trailers, 352 are Claude Opus 5.5,
29 Sonnet 5.5 and 2 Haiku 5.5 (8aaba2e, eefd696). A few early checkpoints name GLM-5.3. The
code, its fixes and all six reviews were written by AI agents. The reviews ran nothing or ran
plain `cargo test`. The fixes of the latest round were committed unbuilt. The same blind spot
(behaviour that shows only when built and run on tokens) is on both sides of the loop.

### 5.2 What a read-only, run-nothing review structurally cannot find

1. **Whether a fix builds or a gate is green.** fce5432's tests did not compile, and C-3's two
   Nix checks fail at HEAD. Today's C found C-3 by reading, but only because it looked at the
   Nix checks. No review before today checked CI status.
2. **Whether a test runs at all.** Silent skips (C-7, C-11, the 11-18 ftpm F1) are visible only
   in a run's report. "243 of the 247 tests in the `cakeys` test binaries pass without running
   anything" (REVIEW_DESIGN D9) was the one time a review counted.
3. **Whether a test fails when the code is wrong.** Without mutation runs, a reader judges
   oracles by eye. The one mutation run (11-15) found 27% of core's mutants surviving, a number
   no review could have produced.
4. **Behaviour on the real modules and hardware** (T-GATED, T-FRIENDLY): ykcs11 on a device,
   real-TPM attestation, the cloud providers, a module that lies about
   `C_DestroyObject` (B-13).
5. **Whether golden data is true.** Profiles and `answers.txt` are regenerated by the code under
   test (C-8, E-7). In 11-18, effective F1, `answers.txt` "had pinned the wrong answer" for
   every all-no profile.
6. **Classes, unless asked.** The 11-23 criteria asked for correctness, complexity and
   consistency per file, not "every path to the same operation" or "which test fails if this is
   flipped". 61 of its 92 findings (66%) have a primary category of design, complexity,
   consistency, CLI or practice; 31 are correctness or security. Today's criteria asked for both
   audits, and today's why-missed codes are what they turned up: T-ABSENT 19, T-INSTANCE 18,
   T-ORACLE 12, T-GATED 11, D-MULTIPATH 9.

### 5.3 Today's findings in code a previous review read and passed (P-REVIEW)

Method: `git blame -w -M -C` on every `path:line` that each finding cites (first four cites),
with each line's commit date compared to the 11-23 review's commit (4304989, 11-19 20:19) and
the 11-18 review's (69ee620). The 11-23 review covered every file ("Files reviewed: every file
in scope").

| | findings |
|---|---:|
| today's findings with blameable cites | 53 (of 54) |
| most cited lines existed when 11-23 reviewed | **44 (83%)** |
| most cited lines existed when 11-18 reviewed too | 35 (66%) |
| tagged P-REVIEW by today's reviewers themselves | 6 |

So 44 of today's 53 findings are in code that the 11-23 review read and passed, and 35 in code
the 11-18 per-file review had also read. The other 9 are mostly in code the 11-23 fixes wrote: A-3, A-4,
A-5, A-7, A-10, C-1, C-3, C-4 and D-1.

Why 11-23 passed them, by today's codes:

- the rule was right at the site read, but missing on another path (D-MULTIPATH 9);
- the sibling of a finding that review itself reported (T-INSTANCE 18: B-5 is 11-23 C-20 in
  `Token::check`, and A-9 is the mirror of 11-23 A-1);
- the tests were not judged: 17 of today's 54 findings (31%) are about the tests themselves,
  against 5 of 92 in 11-23 (A-16, A-18, D-19, D-21, D-23).

## 6. Cross-reference of today's findings

All five of today's files were re-read at the end: 54 findings (A 10, B 13, C 13, D 10, E 8;
2 high, 29 medium, 23 low). "Cited lines from review-fix commits" is `git blame -w -M -C` over
the first four `path:line` cites. A review-fix commit is one of the 80 commits that cite a
review or a finding ID. "Link" is F's reading of each finding against the prior inventory (§1)
and the reviewers' own "Prior fixes re-checked" sections.

| today | sev | link | prior IDs | cited lines from review-fix commits | fix round(s) | reviewer's why-missed codes |
|---|---|---|---|---:|---|---|
| A-1 | medium | in or about a prior fix | 11-23 A-7 (8aaba2e split); 11-15 C2 test lost | 72/81 | 11-15,11-16,11-18,11-23 | P-REVIEW, P-UNRUN, T-ABSENT |
| A-2 | low | in or about a prior fix | 11-23 D-1 (doc not updated) | 1/7 | 11-15 | D-DOCS, T-ABSENT |
| A-3 | low | in or about a prior fix | 11-23 D-1 (instance only) | 19/20 | 11-23 | T-INSTANCE |
| A-4 | low | in or about a prior fix | 11-23 A-16 | 41/41 | 11-23 | D-DOCS, D-PARALLEL |
| A-5 | medium | in or about a prior fix | 11-23 A-2 (wrong) | 25/34 | 11-23 | D-DOCS, P-UNRUN, T-INSTANCE, T-TAUTO |
| A-6 | medium | in or about a prior fix | ISSUES "lock model's replay" (11-18 round) | 3/40 | 11-15 | D-DOCS, T-ABSENT |
| A-7 | low | in or about a prior fix | 11-23 A-3; 11-16 B8 | 51/66 | 11-18,11-23 | D-MULTIPATH, T-INSTANCE |
| A-8 | low | sibling of a prior class | 11-23 A-9 (hand-synced tables) | 11/16 | 11-16,11-23 | D-PARALLEL, T-ABSENT |
| A-9 | medium | in or about a prior fix | 11-23 A-1 (mirror); 11-18 effective F1 | 10/26 | 11-23 | T-INSTANCE, T-ORACLE |
| A-10 | low | in or about a prior fix | 11-23 A-18 | 15/15 | 11-23 | D-DOCS, T-ORACLE |
| B-1 | medium | in or about a prior fix | 11-23 B-3; 11-18 camigrate lib F1/F2 | 32/71 | 11-13,11-15,11-18,11-23 | D-MULTIPATH, P-REVIEW, T-INSTANCE |
| B-2 | medium | in or about a prior fix | 11-23 B-3 (placement), B-27 | 57/76 | 11-15,11-16,11-18,11-23 | D-SEAM, T-ABSENT |
| B-3 | medium | in or about a prior fix | 11-23 B-4 (kept by decision) | 0/30 | – | D-SEAM, T-ABSENT |
| B-4 | medium | sibling of a prior class | 11-18 ops F1 (absent without login) | 2/3 | 11-18,11-23 | D-PARALLEL, T-ORACLE |
| B-5 | low | in or about a prior fix | 11-23 C-20; 11-16 B17 | 4/14 | 11-16 | P-REVIEW, T-INSTANCE |
| B-6 | low | in or about a prior fix | 11-23 B-8; 11-16 B18 | 7/10 | 11-18,11-23 | T-INSTANCE |
| B-7 | medium | in or about a prior fix | 11-23 B-5 (registry) | 1/23 | 11-18 | D-SEAM, T-ABSENT |
| B-8 | medium | no prior link | - | 2/57 | 11-13 | T-ABSENT, T-ORACLE |
| B-9 | low | no prior link | - | 10/19 | 11-15 | D-PARALLEL, T-ABSENT |
| B-10 | medium | in or about a prior fix | 11-18 ykcs11 lib F1 | 1/18 | 11-23 | D-PARALLEL, P-REVIEW, T-INSTANCE |
| B-11 | medium | no prior link | - | 0/5 | – | T-ABSENT, T-FRIENDLY |
| B-12 | medium | in or about a prior fix | 11-23 B-1, B-2 | 0/20 | – | T-ABSENT, T-FRIENDLY, T-INSTANCE |
| B-13 | medium | no prior link | - | 16/49 | 11-13,11-15,11-18,11-23 | D-PARALLEL, T-ABSENT, T-FRIENDLY |
| C-1 | medium | in or about a prior fix | 11-23 C-7 | 34/35 | 11-23 | P-UNRUN, T-ABSENT, T-ORACLE |
| C-2 | low | in or about a prior fix | 11-23 C-3 | 1/1 | 11-18 | D-DOCS, D-PARALLEL, T-INSTANCE |
| C-3 | medium | in or about a prior fix | 11-23 C-16 | 21/24 | 11-11,11-18,11-23 | D-PARALLEL, P-UNRUN, T-TAUTO |
| C-4 | low | no prior link | - | 26/28 | 11-23 | T-GATED, T-ORACLE |
| C-5 | low | sibling of a prior class | 11-23 D-23 | 14/29 | 11-23 | T-ORACLE |
| C-6 | medium | no prior link | - (class of 11-23 B-1/B-2) | 37/154 | 11-15,11-16,11-18,11-23 | T-FRIENDLY, T-GATED |
| C-7 | low | in or about a prior fix | 11-18 ftpm F1 / DESIGN D9 (`opted_in`) | 5/20 | 11-13,11-18 | T-GATED, T-INSTANCE |
| C-8 | medium | sibling of a prior class | 11-18 effective F1 (answers.txt), 11-23 D-6 | 16/40 | 11-13,11-18,11-23 | P-UNRUN, T-GATED, T-TAUTO |
| C-9 | medium | sibling of a prior class | ISSUES "refusals asserted by code or message alone" | – | – | T-ORACLE |
| C-10 | medium | in or about a prior fix | 11-23 C-8; 11-18 flake F1 | 16/24 | 11-18,11-23 | D-DOCS, D-SEAM, P-REVIEW, T-GATED |
| C-11 | medium | sibling of a prior class | 11-18 DESIGN D9 | 2/7 | 11-13 | D-SEAM, T-GATED |
| C-12 | low | no prior link | - | 0/3 | – | D-DOCS, T-GATED |
| C-13 | low | in or about a prior fix | 11-23 decisions batch (6d4beab) | 4/8 | 11-15,11-23 | D-PARALLEL |
| D-1 | high | in or about a prior fix | 11-23 C-1 | 21/21 | 11-13,11-16,11-23 | D-DOCS, P-UNRUN, T-INSTANCE |
| D-2 | medium | in or about a prior fix | 11-23 B-3 | 26/70 | 11-13,11-18,11-23 | D-MULTIPATH, D-PARALLEL, T-GATED, T-INSTANCE |
| D-3 | medium | sibling of a prior class | 11-23 C-2 | 52/99 | 11-13,11-18,11-23 | D-MULTIPATH, T-ORACLE |
| D-4 | low | sibling of a prior class | 11-23 C-2 | 23/31 | 11-13,11-18,11-23 | D-MULTIPATH, T-ABSENT |
| D-5 | medium | in or about a prior fix | 11-23 C-13 | 13/23 | 11-18,11-23 | D-DOCS, T-FRIENDLY, T-INSTANCE |
| D-6 | low | sibling of a prior class | 11-23 C-2 | 7/17 | 11-13,11-18,11-23 | D-MULTIPATH, T-ABSENT |
| D-7 | medium | sibling of a prior class | 11-11 S5/S6 (open-world policy) | 2/8 | 11-18 | D-TYPES, T-ABSENT, T-FRIENDLY |
| D-8 | low | sibling of a prior class | 11-23 C-1 | 11/32 | 11-13,11-16,11-23 | D-MULTIPATH, T-ABSENT |
| D-9 | low | in or about a prior fix | 11-23 C-21 | 9/16 | 11-13,11-18,11-23 | T-ABSENT |
| D-10 | low | in or about a prior fix | 11-18 transport.rs F1 | 11/32 | 11-15,11-18,11-23 | D-MULTIPATH, T-ABSENT, T-TAUTO |
| E-1 | low | in or about a prior fix | 11-23 D-8 | 67/67 | 11-13,11-18 | T-ORACLE |
| E-2 | high | in or about a prior fix | 11-23 D-4 | 0/6 | – | D-MULTIPATH, P-REVIEW, P-UNRUN, T-INSTANCE, T-ORACLE |
| E-3 | medium | in or about a prior fix | 11-23 D-3 | 0/74 | – | T-FRIENDLY, T-INSTANCE |
| E-4 | medium | in or about a prior fix | 11-23 D-2 | 2/4 | 11-23 | D-TYPES, T-INSTANCE |
| E-5 | medium | no prior link | - | 0/3 | – | D-DOCS, T-GATED, T-TAUTO |
| E-6 | low | in or about a prior fix | 11-23 D-1 | 7/32 | 11-16,11-23 | T-FRIENDLY, T-GATED |
| E-7 | medium | in or about a prior fix | 11-23 D-6, C-8 | 9/32 | 11-15,11-23 | D-DOCS, P-UNRUN, T-GATED, T-ORACLE, T-TAUTO |
| E-8 | low | in or about a prior fix | 11-23 D-6 | 3/22 | 11-23 | D-DOCS, D-PARALLEL, T-INSTANCE |

### 6.1 Counts

| Measure | Count |
|---|---:|
| In or about a prior fix: the fix was incomplete, wrong or regressed, or the finding is its direct consequence | **35/54 (65%)**, of which **31 concern the 11-23 round's fixes** and 4 the 11-18 round's |
| Sibling of a prior class in the same area, not tied to one fix | 11/54 (20%) |
| No prior link | 8/54 (15%): B-8, B-9, B-11, B-13, C-4, C-6, C-12, E-5 |
| Cites at least one line last written by a review-fix commit | 46/53 (87%) |
| Most cited lines last written by a review-fix commit | 24/53 (45%) |
| Most cited lines existed when 11-23 reviewed (P-REVIEW, §5.3) | 44/53 (83%) |
| About the tests themselves (oracle, gating, golden data, deleted tests) | 17/54 (31%) |

Today's reviewers' own "why missed" codes (multi-label): T-ABSENT 19, **T-INSTANCE 18**,
D-DOCS 13, T-ORACLE 12, D-PARALLEL 11, T-GATED 11, D-MULTIPATH 9, **P-UNRUN 8**, T-FRIENDLY 8,
P-REVIEW 6, T-TAUTO 6, D-SEAM 5, D-TYPES 2. By F's D-FAILOPEN definition, 10 more fail open:
A-9, B-4, B-6, B-13, D-1, D-7, D-8, D-10, E-2 and E-4.

Re-checks of prior fixes by today's reviewers (from their "Prior fixes re-checked" sections;
an ID checked by two reviewers counts once, at the worse verdict):

| Verdict | Prior IDs | Count |
|---|---|---:|
| holds | 11-23 A-4, A-5, A-10, A-11, A-12, A-13, A-15, A-17; B-2, B-5, B-6, B-7, B-8, B-9, B-10, B-11, B-12, B-13, B-14, B-16, B-17, B-18, B-22, B-24, B-25, B-26, B-27 (B: "the class came back" as B-2); C-2, C-4, C-5, C-9, C-10, C-11, C-12, C-14, C-19, C-22; D-5, D-6 (E: "the class remains"), D-8, D-11, D-12, D-13, D-14, D-15, D-19, D-22, D-24; 11-18 transport F1, from_files F1, F2 | 51 |
| instance only / partial | 11-23 A-1, A-3, A-7, A-8, A-9, A-14, A-16, A-18; B-1, B-3; C-1, C-3, C-7, C-8, C-13, C-20, C-21, C-23; D-1, D-2, D-3, D-4, D-17, D-20; 11-18 ykcs11 lib F1 | 25 |
| wrong or regressed | 11-23 A-2 (bypassable by locator spelling), C-16 (two Nix checks now fail) | 2 |

So 27 of 78 re-checked fixes (35%) are instance only, partial, wrong or regressed. The share
rises with severity. Of the 29 medium-or-higher 11-23 findings whose fix was re-checked,
**16 (55%) did not hold**: A-1, A-2, A-3, A-7, A-8, B-1, B-3, C-1, C-3, C-7, C-8, C-23, D-1,
D-2, D-3 and D-4. Of the low ones, 11 of 49 (22%) did not hold. The fixes that hold are mostly
doc, dead-code and single-site edits. The ones that fail are rules with more than one entry path.

## 7. Synthesis: ranked root causes and structural changes

The causes are ranked by how much of the evidence each explains. Each comes with the structural
change that breaks it, its cost, and how to check it worked. The five area reviewers reached the
same causes independently: every one lists instance-scoped fixes; B and D list rules at call
sites; A and C list unbuilt changes; B, C, D and E list a friendly or tautological test oracle.

### R1. Fixes close the reported instance, and the regression test pins the instance (T-INSTANCE)

Evidence:

- Fix audit (§2, n = 41):
  - 22 (54%) were later found instance-only or wrong at the same rule, and 36 (88%) had a later
    sibling.
  - Only 4 of 35 regression tests (11%) cover the class.
- The 11-18 round is the control: every fix had a test checked red by restoring the old code,
  yet 6 of 11 are instance-only.
- Today (§6):
  - 35 of 54 findings (65%) are in or about a prior fix; 31 of those concern the 11-23 round.
  - 16 of 29 (55%) re-checked medium-or-higher 11-23 fixes did not hold.
  - T-INSTANCE is the second most common "why missed" code (18).
- 17 sibling chains (§1.4); 16 reach 11-23 or today. Examples:
  - by-name retry: 11-16 B18 → 11-23 B-8 → today B-6;
  - RSA size: 11-16 B17 → 11-23 C-20 → today B-5;
  - transport binding: 11-18 F3 → 11-23 C-1 → today D-1;
  - scratch guard: 11-23 D-1 → today A-3 and E-6;
  - verdict from absence: 11-18 effective F1 → 11-23 A-1 → today A-9.

Change: a fix protocol that makes the class the unit of work. A fix commit must:
(a) name the class in one sentence;
(b) list every site of the class, found with `rg` or `ast-grep`, in the commit message;
(c) either remove the class by construction (a type, one function at the operation) or add one
table-driven test over the whole list;
(d) show the test failing on the old code: cargo-mutants `--in-diff` on the PR, or a recorded
revert run.
Cost: about 1.5× the work per fix, nothing else.
Verify: in the next review, prior fixes made under the protocol come back with zero T-INSTANCE
verdicts. Today's baseline is 25 instance-only out of 78 re-checks.

### R2. A rule lives at one call site or entry path, not at the operation; the plan mirrors execution by hand (D-MULTIPATH, D-PARALLEL)

Evidence:

- D-MULTIPATH is in 6 of 6 reviews (22 hand-classified findings), and D-PARALLEL in 6 of 6 (31).
- The 11-18 review named the class (REVIEW_DESIGN D1, "Rules that guard irreversible writes
  live in planners, not at the write site") and prescribed the class fix. The fixes put the rule
  at the reported sites. Since then 11-23 found 6 more (A-2, A-10, A-12, B-3, C-2, C-23), and
  today 10 (A-7, B-1, B-2, D-2, D-3, D-4, D-6, D-8, D-10, E-2).
- At least 6 of the 16 medium-or-higher 11-23 fixes that failed are this class: the rule was
  fixed on one path or site and is still missing on another. They are A-3 (→ today A-7), B-1
  (vendor path → B-12), B-3 (→ B-1, B-2, D-2), C-23 (→ D-2, D-3), D-2 (→ E-4) and D-4 (2 of
  about 20 sites → E-2).
- D.md: "The plan is a hand-written mirror of the write-time checks". The dry-run twin accepts
  `dry 0 → real ∈ {0, 22, 10, 13}`, so the twin cannot catch a divergence.
- `camigrate/src/lib.rs` has the most churn of any source file, with 17 prior findings and 5
  today.

Change: one plan/execute path.

- Each write (pkcs11 `create`, `delete`, import, unwrap; camigrate's import, export, migrate and
  transport) is an operation value. The constructor or a `check(&op)` runs every rule:
  placement, attestation, locator free, key size, identity, transport binding.
- Both `--dry-run` and the real run call that function. The token-writing functions are
  reachable only through `execute(op)`, enforced by module privacy.
- The dry-run twin becomes strict: dry 0 ⇒ real 0, except for an enumerated list of
  material-only outcomes.

Cost: the largest item. camigrate `lib.rs` and `landing.rs` and pkcs11 `ops` are about 2–3k
lines to restructure, and today's D-1 to D-6 and B-1/B-2 are fixed as a side effect.
Verify: a property or table test that, for every verb × path, runs plan and execute under
p11-fault lies and asserts the same verdict. Also `rg` shows no call of the write functions
outside `execute`.

### R3. Changes land without the deciding gate, and nothing blocks on the gate (P-UNRUN)

Evidence:

- Main's `checks` has been red on every push since 11-19 (4 of 4); PR #5 was merged red
  (lead-verified CI).
- 11 of 15 audited 11-23 fixes (73%) are in commits that say "Not built or tested here" or "Not
  built or run here", and the next commit fixed core tests that did not compile.
- The 11-18 round's three WIP checkpoints were "not gated".
- 8aaba2e deleted 8 tests with no signal, which undid the 11-15 C2 regression test.
- 84% of 406 commits say nothing about what ran.
- About 82% of integration tests need tokens, swtpm or hardware, and skip and pass under the
  per-change step (§4.2). The darwin dev gate does not compile tpm2.
- Today: P-UNRUN 8 (A-1, A-5, C-1, C-3, C-8, D-1, E-2, E-7), and C-3's two Nix checks fail at
  HEAD.

Change, in this order:

1. Branch protection: no direct pushes to `main`, and `checks/light` and `checks/vm` required
   green before merge.
2. A nextest JUnit summary in the crane check that fails on any skipped test in the token tier,
   and on a test count below the base branch's unless the commit lists the removed names.
3. A pre-push hook running `checks-crane-only`.
4. Fix C-3's two checks so main is green.

Cost: about half a day. It is the cheapest change and comes first, because R1 and R2 cannot be
checked without it.
Verify: 100% of merges to main have green required checks (`gh api …/commits/<sha>/status`);
skip count 0; no unexplained test-count drops.

### R4. Absence, error and "unknown" become an answer (D-FAILOPEN)

Evidence:

- The largest class in the hand-classified set: 49 of 265 (18%), in 6 of 6 reviews, and the
  largest in both 11-11 (15) and 11-23 (18).
- Today it covers 10 more: A-9, B-4, B-6, B-13, D-1, D-7, D-8, D-10, E-2, E-4.
- The shapes repeat:
  - `Option<bool>` read as `== Some(true)` (D-7);
  - retry or "no" after any failure (B-6, E-2);
  - first row by label (11-23 B-13);
  - module-asserted data trusted (11-11 H1b, 11-18 esys F1, 11-23 B-1/B-2);
  - `CKR_OK` on destroy trusted (B-13).

Change:

- A tri-state verdict type (`Yes`, `No(evidence)`, `Unknown(reason)`) with no `Default`, used by
  profile, caprobe and the planners.
- Typed `CK_RV` on every token error.
- clippy `disallowed-methods` (`unwrap_or`, `unwrap_or_default`, `.ok()` on token reads) in
  core, pkcs11, profile and caprobe.
- A p11-fault "error at every call" sweep: for each `C_*` function and each call index, inject
  `CKR_DEVICE_ERROR`, and assert a non-zero exit with lock and token unchanged, or a verdict of
  `Unknown`.

Cost: 1–2 days, plus the sweep's CI time.
Verify: the sweep's cell count, and zero cells that answer yes or no.

### R5. The test oracle is friendly, tautological or gated (T-FRIENDLY, T-TAUTO, T-ORACLE, T-GATED)

Evidence:

- T-GATED is in 4 of 6 reviews. Today's codes: T-ORACLE 12, T-GATED 11, T-FRIENDLY 8, T-TAUTO 6.
- 39 of 131 cli tests are exit-code or prose only (C-9). Golden tables are regenerated in the
  same commit as the behaviour in 36 of 47 commits (C.md).
- `answers.txt` had pinned the wrong answer (11-18).
- The lie table covers 3 verbs × 1 object class (C-6). The ykcs11 device, real TPM and cloud
  paths are never automated.
- The only mutation run missed 27% of core's mutants. Mutation testing covers neither pkcs11
  nor cli, caprobe or the providers, and gates nothing.

Change:

- A liar-module matrix in CI: generate p11-fault plans over verb × object class × lie (wrong
  key, wrong attribute, `CKR_OK` on a destroy that did not, device error). Assert exit code
  **and** lock and token state through one shared `state()` helper.
- cargo-mutants as a gate on the critical crates: core, pkcs11 `token/{identity,possession}`
  and `ops`, camigrate, profile and caprobe's verdict code. `--in-diff` on PRs with zero new
  survivors; the full run weekly.
- Golden data changes in a separate commit from behaviour, and at least the identity values
  checked against an independent oracle (OpenSSL).

Cost: 2–3 days for the matrix generator; the mutation gate is configuration plus CI time.
Verify: the matrix cells covered over the total, and the mutation score on the critical crates
per PR.

### R6. Scope grows faster than the loop closes

Evidence:

- 461 commits and about 182k added lines in 11 active days (§3).
- The 11-13 review flagged that 40% of the code was beyond "pin and verify"; the next two days
  added camigrate (6.8k), caprobe (3.9k), p11-fault (2.5k) and two cloud providers.
- Each review window adds more source than its fixes touch.
- Fix batches run 56–348 files per commit and cannot be reverted per finding.
- 45% of HEAD's crate lines were last written by a review-fix commit, and today's cited lines
  are 1.3× over-represented in them.

Change:

- Freeze features until R2 to R4 land and main has been green for a week.
- One class per fix commit, so each can be reverted and mutation-checked on its own.

Cost: schedule only.
Verify: the next review's new medium-or-higher findings in frozen code against today's 31
medium-or-higher.

### R7. The review is read-only and asks what it asks (P-REVIEW)

Evidence:

- 44 of 53 of today's findings (83%) are in code the 11-23 review read and passed; 35 (66%)
  were also read by 11-18.
- No review before today asked "which test fails if this is flipped" or "which other path
  reaches this operation". 66% of 11-23's findings were design, complexity, consistency, UX or
  practice.
- With those two questions added, today's reviewers found 17 findings about the tests (31%,
  against 5% in 11-23) and 9 D-MULTIPATH.
- No review checked CI, built a fix or counted skips. The same agents wrote the code and the
  reviews (§5.1).

Change: keep today's mutation and entry-point criteria as standing criteria. Also give every
review three mechanical inputs it does not have today: the gate result at the reviewed commit,
the mutation survivors for the reviewed crates, and the skip and test counts.
Verify: the share of findings with P-REVIEW in the following review.

### Order and cost

| Step | Change | Cost | Breaks |
|---:|---|---|---|
| 1 | R3: branch protection, required green CI, skip-count and test-count gate; fix the two red checks | ½ day | P-UNRUN; lost tests |
| 2 | R1: class-level fix protocol, with cargo-mutants `--in-diff` as the revert check | config + 1.5× per fix | T-INSTANCE |
| 3 | R2: one plan/execute path, with rules on the operation; strict dry-run twin | 3–5 days | D-MULTIPATH, D-PARALLEL (plan vs run) |
| 4 | R4 + R5: tri-state verdict type, error sweep, liar-module matrix, mutation gate on the critical crates | 3–5 days | D-FAILOPEN, T-FRIENDLY, T-ORACLE |
| 5 | R6: feature freeze until 1–4 hold | schedule | velocity |
| 6 | R7: reviews get gate, mutation and skip data, and keep the mutation and entry-point criteria | per review | P-REVIEW |
