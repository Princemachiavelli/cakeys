# Lock-file prior art and what it implies for the cakeys `keys.lock`

Scope note: cakeys facts are cited to local files in this repository (`docs/DESIGN.md`,
`crates/core/src/config.rs`, `crates/core/src/id.rs`, `crates/pkcs11/src/ops.rs`, `nix/lib.nix`,
`examples/yubikey-secureboot.lock`) at commit `8889898`. External facts are cited to the page that
was fetched. Where a fact comes only from a search-result summary, not a fetched primary page, it is
labelled **(search summary)**.

## Q1. What do mature lock files record per entry (identity, source, integrity, resolved inputs)?

### Takeaway

Every mature format separates **what was asked for** (the manifest or `original` spec), **what it resolved to** (the
locked, final coordinates), and **an integrity digest of the content**. The better ones also record a
digest of the *inputs* that produced each entry, so staleness is detected per entry. cakeys already has all
three layers: `keys.toml`; realisations (locator/URI); and `objects.*.ids` plus `specDigest`. But the per-entry
input digest covers only part of the realisation's inputs.

### Cited Findings

- **Go `go.sum`**:
  - Each line is "a module path, a version (possibly ending with `/go.mod`), and a hash".
  - The `/go.mod` suffix means the hash covers only the module's `go.mod` file. Otherwise it covers the files in the module `.zip`. So one coordinate has two separately hashed artefacts. — [Go Modules Reference, go.sum files](https://go.dev/ref/mod#go-sum-files)
- **Go checks against the main module's `go.sum` only**: "To avoid the need to trust other modules, the `go` command verifies hashes using the main module's `go.sum` whenever it accesses a file in the module cache." — [Go Modules Reference, Authenticating modules](https://go.dev/ref/mod#authenticating)
- **Nix `flake.lock`**:
  - It is a JSON graph of nodes. Each node has `inputs` (name → node label), `original` ("the original input specification from `flake.nix`") and `locked` ("the locked input specification, as a set of `builtins.fetchTree` arguments").
  - `locked` attributes are "considered 'final'" and are the only ones passed to `outputs`.
  - `locked` carries an SRI `narHash` (e.g. `sha256-OnpE…`), which "allows the store path to be computed".
  - The root node has no `original`/`locked`, because "we cannot record the commit hash or content hash of the root flake".
  — [nix flake manual, Lock files](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-flake)
- **Bazel `MODULE.bazel.lock`** has two parts: hashes of remote resolution inputs, and per-extension inputs and outputs.
  - `registryFileHashes` "contains the hashes of all files from remote registries accessed during module resolution", including recorded "not found" results.
  - Each module extension entry records:
    - `bzlTransitiveDigest`, "the digest of the extension implementation and the .bzl files transitively loaded by it";
    - `usagesDigest`, a digest of the extension's usages, including all tags;
    - "further unspecified fields that track other inputs to the extension";
    - its outputs, `generatedRepoSpecs`.
  - OS- or arch-dependent results get "multiple entries … named after the OS, architecture, or both".
  — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **npm `package-lock.json`** `packages` entries record:
  - `version`;
  - `resolved` ("The place where the package was actually resolved from");
  - `integrity` (a `sha512` or `sha1` SRI string "for the artifact that was unpacked in this location");
  - `link`, `dev`, `optional`.
  — [npm package-lock.json docs](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json)
- **PEP 751 `pylock.toml`**:
  - It is "designed to not require a resolver at install time", which "greatly simplifies reasoning about what would be installed".
  - Each package carries a `marker` for when it applies. "All packages to be installed MUST narrow down to a single entry at install time."
  - Dependency edges are "purely informational for auditing purposes"; tools "MUST NOT use this information when doing installation".
  — [PEP 751](https://peps.python.org/pep-0751/)
- **SLSA v1.0 provenance** splits `buildDefinition` from `runDetails`.
  - `buildDefinition` "describes all of the inputs to the build". It holds `buildType`, `externalParameters`, `internalParameters` and `resolvedDependencies`.
  - `runDetails` is "Details specific to this particular execution of the build": `builder`, `metadata` (invocationId, startedOn, finishedOn) and `byproducts`.
  — [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- **Nix CA-derivation realisations**:
  - A realisation maps an output id `(hashModulo(drv), output)` to an `outputPath`, with a `dependencies` map.
  - Content-addressed realisations "must be signed as there's no simple deterministic relation between a derivation and its output paths".
  — [Nix RFC 0062](https://github.com/NixOS/rfcs/blob/master/rfcs/0062-content-addressed-paths.md)
- **cakeys today**:
  - `objects.<name>` holds `type`, `commitmentLabel` and `ids` (scheme → SRI).
  - `realisations.<spec>.<token>` holds:
    - `specDigest`, `mode`, `publicOnly` and `uri`;
    - `module`, `token`, `provider` and `cakeysVersion` (provenance);
    - `mechanisms`.
  — `crates/core/src/config.rs` (`Lock`, `LockObject`, `LockRealisation`); `docs/DESIGN.md` §4.2

### Inferences

- **The layers map onto cakeys** as follows:

  | Prior-art layer | cakeys field |
  |---|---|
  | `original` | `keys.toml` spec + locator |
  | `locked` | `uri`, `token.serial` |
  | integrity / `narHash` | `objects.*.ids` |
  | Bazel `usagesDigest` | `specDigest` |
  | SLSA `runDetails` | `module` / `provider` / `cakeysVersion` |

- **Nix leaves the root flake unhashed, and cakeys does the same with `keys.toml`.** Nix does not hash the root flake.
  Likewise cakeys has no whole-`keys.toml` hash, and instead uses per-entry input digests, as Bazel does. That choice is
  consistent with prior art and is better for merges than Poetry-style whole-manifest hashing (Q5).
- **A realisation does not name its object.** In cakeys the object↔realisation edge exists only in `keys.toml`
  (`specs.<s>.object`). flake.lock (`inputs` edges) and RFC 62 (`dependencies`) record their graph edges *inside* the
  lock, so the lock alone can be audited (see the cakeys gaps under Q6).

### Gaps

- I did not fetch pnpm's or Yarn Berry's lockfile specs (e.g. Yarn's `__metadata.cacheKey` or pnpm's `settings`), so their per-entry fields are not covered.
- I did not fetch Cargo.lock's per-package field documentation. From the format itself: `name`, `version`, `source`, `checksum`, `dependencies`. That is not verified against a fetched page in this session.

## Q2. What makes a lock "complete" rather than "underdefined"? Formal and semi-formal treatments

### Takeaway

No source gives a single formal definition of lock completeness. Several converge on a usable semi-formal one:

1. Every input that can change the output is either recorded with a digest or fixed by a named, immutable definition.
2. The recorded set is explicit, so a verifier can **reject anything it does not understand**.
3. Execution-specific data is quarantined from identity.

### Cited Findings

- **Reproducible builds**:
  - Definition: "A build is reproducible if given the same source code, build environment and build instructions … any party can recreate bit-by-bit identical copies of all specified artifacts."
  - The relevant environment attributes "would usually include dependencies and their versions, build configuration flags and environment variables … as far as they are used by the build system". "It is preferable to reduce this set of attributes."
  - These, the instructions and the source are "defined by the authors or distributors".
  — [reproducible-builds.org definition](https://reproducible-builds.org/docs/definition/)
- **SLSA**:
  - External parameters "MUST be complete at SLSA Build L3, meaning that there is no additional mechanism" for external influence. At lower levels "the completeness MAY be best effort".
  - "Verifiers SHOULD reject unrecognized or unexpected fields within `externalParameters`."
  - `internalParameters` "MAY be necessary for reproducing the build", but their primary purpose is "debugging, incident response, and vulnerability management".
  — [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- **Bazel's `error` lockfile mode** fails "if any information consulted during resolution is missing or out-of-date". It "never changes the lockfile or performs network requests during resolution". "Superfluous information is ignored, not reported." — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **Bazel has a reproducibility contract for module extensions.** Extensions that declare `reproducible = True` "promise that they will always create the same repositories when given the same inputs" and are then not locked. — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **Nix FODs**:
  - A fixed-output derivation is defined by `outputHash`, `outputHashAlgo` and `outputHashMode`.
  - `outputHashMode` "specifies how the files of a content-addressing derivation output are digested to produce a content address". Modes: `flat` (default), `recursive`/`nar`, `text` (experimental), `git` (experimental).
  - So the digest *method* is part of the declaration, not implied.
  — [Nix manual, advanced attributes](https://nix.dev/manual/nix/latest/language/advanced-attributes)
- **Nix CA store**:
  - RFC 62 contrasts the input-addressed ("extensional") store with the content-addressed ("intensional") one.
  - CA paths come from output content. Self-references are handled by hash rewriting, which the RFC calls "obviously a hack" that may miss references inside compressed archives.
  — [Nix RFC 0062](https://github.com/NixOS/rfcs/blob/master/rfcs/0062-content-addressed-paths.md)
- **PEP 751** rejected having installers resolve dependencies, because that "complicates auditing a lock file by requiring much more mental effort". — [PEP 751](https://peps.python.org/pep-0751/)
- **The cakeys completeness claim**:
  - DESIGN §10 says the lock records "the values that determine each ID: scheme name, commitment label and the hash itself. Everything else is fixed by definition."
  - That rests on immutable scheme definitions, pinned by known-answer tests: `scheme_definitions_are_pinned` and `commitment_mechanisms_are_pinned`.
  — `docs/DESIGN.md` §10

### Inferences

- **Proposed operational test for "not underdefined"**, assembled from SLSA L3 completeness, Bazel `error` mode,
  reproducible-builds, Nix FOD and PEP 751. For every lock field and every value an ID depends on, exactly one of these holds:
  - **(a)** it is recorded in the lock and compared on verify;
  - **(b)** it is fixed by a versioned, immutable definition named in the lock (scheme name, lock `version`, spec-digest `"v":1`);
  - **(c)** it is declared provenance: never compared for success, at most a warning;
  - **(d)** it is declared *out of scope*, with a stated reason.

  "Something else in the change caused the hash break" is then provable: if all (a) fields are unchanged and all (b)
  names are known, a mismatch can only come from the token's material.
- **The cakeys ID computation already meets (a)/(b)**: scheme name, commitment label, object type and pinned scheme
  definitions. It is closer to an FOD (declared method plus expected hash) than to a resolver lock.
- **The realisation layer does not yet fully meet the test**: locator, `publicOnly`, object binding and `mechanisms`
  have no declared class (see Q5 and Q6).
- **Provenance can still matter for reproduction.** SLSA's `internalParameters` "MAY be necessary for reproducing"
  is a warning: data cakeys calls provenance (module and provider) can affect *whether* an ID can be recomputed, and
  which schemes. The provider fix-up rule (DESIGN §6.2) is what makes it safe to treat them as provenance.
  That rule is a definitional premise, and it should be listed among the frozen premises.

### Gaps

- I did not fetch Dolstra's PhD thesis ("The Purely Functional Software Deployment Model", 2006), which treats extensional and intensional stores formally. RFC 62 is the secondary source used here.
- I found no formal (proof-style) definition of lock-file completeness in any source. The test above is a synthesis.
- in-toto layouts/links and Debian `.buildinfo` were not fetched. The reproducible-builds definition page does not mention `.buildinfo`.

## Q3. How do tools pin algorithm identity, and how do they handle algorithm upgrades?

### Takeaway

Every robust scheme puts an **explicit algorithm or version tag next to the digest**. They differ on *who decides what
counts as a match*:

- **SRI**: the strongest known algorithm wins; unknown algorithms are ignored.
- **in-toto**: ANY accepted algorithm matching is enough; unknown ones are ignored.
- **Go**: `h1` only today, with `h2` reserved for the future.

The upgrade path is always **add a new tag, never redefine an old one**. cakeys already follows this with scheme
names and the SRI prefix.

### Cited Findings

- **Go**: "The hash column consists of an algorithm name (like `h1`) and a base64-encoded cryptographic hash … Currently, SHA-256 (`h1`) is the only supported hash algorithm. If a vulnerability in SHA-256 is discovered in the future, support will be added for another algorithm (named `h2` and so on)." — [Go Modules Reference, go.sum files](https://go.dev/ref/mod#go-sum-files)
- **SRI format and required algorithms**: integrity metadata uses the CSP `hash-source` form, i.e. algorithm, `-`, base64. User agents "MUST support the SHA-256, SHA-384, and SHA-512". — [W3C SRI 2 (WD 2026-03-20)](https://www.w3.org/TR/sri-2/)
- **SRI with several hashes**:
  - "the user agent will choose the strongest hash function in the list".
  - An unsupported algorithm "acts like no integrity value was provided".
  - Multiple digests are explicitly "to provide agility in the face of future cryptographic discoveries".
  — [W3C SRI 2](https://www.w3.org/TR/sri-2/)
- **SRI options**: an `option-expression` syntax is reserved, but no options are defined. User agents "MUST ignore all unrecognized" options. — [W3C SRI 2](https://www.w3.org/TR/sri-2/)
- **in-toto DigestSet**:
  - It maps algorithm name → digest.
  - Consumers "MUST only accept algorithms that they consider secure and MUST ignore unrecognized or unaccepted algorithms".
  - "Two DigestSets SHOULD be considered matching if ANY acceptable field matches."
  - "most applications SHOULD NOT accept 'md5'".
  - It also has non-hash identifiers (`gitCommit`, `dirHash`) whose encoding is "identifier-specific".
  — [in-toto DigestSet spec](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)
- **Nix**:
  - `outputHash` may be SRI, in which case `outputHashAlgo` may be `null` "because the SRI format determines the algorithm".
  - Supported algorithms: `blake3`, `sha1`, `sha256`, `sha512`.
  - The digest *method* is a separate field, `outputHashMode`.
  — [Nix manual, advanced attributes](https://nix.dev/manual/nix/latest/language/advanced-attributes)
- **flake.lock** stores `narHash` as SRI (`sha256-…`). — [nix flake manual](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-flake)
- **TUF**:
  - Target hashes are "a dictionary that specifies one or more hashes", plus a `length`.
  - Clients must "verify that its hashes match". The spec does not state whether all or any must match.
  — [TUF specification](https://theupdateframework.github.io/specification/latest/)
- **Ecosystems vary in hash algorithm.** SHA-256 in go.sum, Cargo.lock and uv.lock; SHA-512 in npm and pnpm. Yarn Berry "changed how checksums are computed", which broke tools expecting npm-compatible hashes. — [Nesbitt, Lockfile format design and tradeoffs (2026-01-17)](https://nesbitt.io/2026/01/17/lockfile-format-design-and-tradeoffs.html)
- **cakeys pins algorithm identity at two levels.**
  - **Outer digest**: an SRI `sha256-<base64>` prefix on every ID.
  - **Inner computation**: an immutable scheme name, such as the HMAC hash per key type, the CMAC, or the KCV block.
  - "A changed computation is a *new* scheme name, never an edit."
  - Matching rule in `ops.rs` `reconcile`:
    - every computed-and-locked scheme must be equal, so any mismatch is exit 10;
    - at least one must match;
    - a scheme computed but not yet locked is a note;
    - a locked scheme unknown to this cakeys is a warning.
  — `docs/DESIGN.md` §3.1, §3.5, §10; `crates/pkcs11/src/ops.rs` `reconcile`

### Inferences

- **The scheme name plays the role of Go's `h1` and Nix's `outputHashMode`; the SRI prefix plays the role of `outputHashAlgo`.**
  For commitment schemes the SRI prefix describes only the *outer* SHA-256 over the token output. The HMAC/CMAC algorithm is implied by scheme
  plus `type`. That is acceptable only because `type` is recorded and compared (DESIGN §4.2). It should be stated as such in §10.
- **The cakeys matching rule is stricter than in-toto's "ANY" and safer for identity.** in-toto's rule tolerates
  a mismatching weak algorithm when a strong one matches. cakeys fails on any mismatch among computed schemes. Keep it
  stricter, and document the difference deliberately.
- **Missing: a policy for weak or deprecated schemes.** in-toto lets consumers refuse algorithms they "consider
  [in]secure", and SRI picks the strongest. cakeys has a mode ordering (`direct` > `commitment` > `wrap-rebind` …) with downgrade refusal, but
  no notion of a *scheme* being deprecated. For example, a future `kcv-ecb` weakness would have no way to say "this scheme alone no
  longer proves identity". Recommendation: a frozen per-scheme strength or "sufficient alone" table in code, pinned by test.
- **ID values are not checked for well-formedness.** `LockObject.ids` is `BTreeMap<String,String>` with no syntax check. Nix,
  SRI and in-toto all parse the algorithm token. A lock value like `sha512-…` or a typo would surface only as a hash
  mismatch (exit 10), not as an invalid lock. Recommendation: parse each value as SRI with an allowed algorithm set at load
  (`Lock::validate`).

### Gaps

- I found no source describing how Go would *migrate* existing `h1` lines if `h2` were introduced, e.g. whether both would be kept. The reference only reserves the name.
- I did not verify npm's behaviour when `integrity` holds several space-separated SRI tokens.

## Q4. Format versioning, unknown fields and migration

### Takeaway

The mature pattern is a schema version (not a tool version), with per-change variants:

- readers accept older variants and keep writing the version they found;
- a new variant becomes the default only later;
- the major/minor split decides "refuse" vs "warn" for content a reader does not know.

cakeys's `version = 1` currently names several schemas ("Unpublished, so its schema changes in place"). By the
user's own standard that is the most underdefined part of the lock.

### Cited Findings

- **Cargo** (search summary):
  - Every lock format change is a new `ResolveVersion` variant.
  - V1 had no version marker and kept checksums in `[metadata]`.
  - V2 (1.38) was designed to reduce merge conflicts and was the default for new lockfiles in 1.41–1.52.
  - V3 was the default in 1.53–1.82.
  - V4 is the current default. "Became default in 1.83" is my inference from the 1.82 end of the V3 range.
  - V5 is unstable behind `-Znext-lockfile-bump`.
  - "If Cargo finds the new version it'll keep using it, but otherwise it continues to use whatever format it previously found". Bumps are deliberately gradual because format changes "can cause quite a bad experience for end users who use different versions of Cargo".
  - Lockfiles without a marker are treated as V1.
  — [ResolveVersion docs (beta)](https://doc.rust-lang.org/beta/nightly-rustc/cargo/core/resolver/enum.ResolveVersion.html), [cargo lockfile_compat tests](https://rust.googlesource.com/cargo/+/HEAD/tests/testsuite/lockfile_compat.rs) **(search summary; the docs pages 404'd when fetched directly)**
- **npm** `lockfileVersion`:
  - 1 is for npm v5/v6.
  - 2 is for npm v7/v8, "Backwards compatible to v1 lockfiles".
  - 3 is for npm v9+, "Backwards compatible to npm v7".
  - "npm will always attempt to get whatever data it can out of a lockfile."
  — [npm package-lock.json docs](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json)
- **PEP 751**:
  - `lock-version` starts at `"1.0"`.
  - If a tool supports the major but not the minor version, it "SHOULD warn when an unknown key is seen".
  - An unsupported major version "MUST raise an error".
  - Tool-specific data lives in `[tool]` tables, which "MUST be disposable (i.e. it MUST NOT affect installation)".
  — [PEP 751](https://peps.python.org/pep-0751/)
- **TUF**:
  - `spec_version` follows SemVer 2.0.0. Clients "MUST verify that 'spec_version' matches the expected version number", but "Adopters are free to determine what is considered a match".
  - Undefined key/value pairs are not ignored: implementers "must include the data when calculating hashes or verifying signatures" and "must preserve the data when re-serializing".
  - Extension data goes in `custom`, which is "opaque to the framework".
  — [TUF specification](https://theupdateframework.github.io/specification/latest/)
- **Bazel**: "the lockfile is specific to the Bazel version", and it changes even between backward-compatible releases. The docs do not describe `lockFileVersion` migration rules. — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **SLSA**: verifiers "SHOULD reject unrecognized or unexpected fields within `externalParameters`". — [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- **Nesbitt's recommendations**:
  - "Version the schema, not the tool." Cargo's schema-only version field "causes the least friction".
  - Bundler's `BUNDLED WITH` (the tool version) "causes conflicts across developers".
  - Yarn v1 has no schema version, and Poetry has only a comment that tooling cannot parse reliably.
  — [Nesbitt 2026](https://nesbitt.io/2026/01/17/lockfile-format-design-and-tradeoffs.html)
- **Poetry** (search summary of source code): `[metadata]` holds `lock-version` ("1.1", "2.0"). The reader falls back to "1.0" when it is absent. — [poetry locker.py](https://github-redirect.dependabot.com/python-poetry/poetry/blob/6dc4c516cf4228b68d56c532b8b7db15dcf83413/src/poetry/packages/locker.py) **(search summary)**
- **cakeys today**:
  - `LOCK_VERSION = 1`, with the comment "Unpublished, so its schema changes in place".
  - `version` has `#[serde(default = "lock_version")]`, so a lock with **no** `version` reads as the *current* version.
  - Any other version is refused.
  - Every lock struct is `deny_unknown_fields`.
  - Scheme names inside `ids` are open: unknown ones produce a warning.
  - `commitmentLabel` (`90d5353`) and `type`, provenance and `specDigest` comparison (`8889898`) were all added without a version bump.
  — `crates/core/src/config.rs`; `git log -- crates/core/src/config.rs`

### Inferences

- **`version = 1` is ambiguous.** It denotes at least three schemas: before `commitmentLabel`, before `type`, and the current one.
  - A lock written between those commits validates differently today. For example, a v1 lock with commitment IDs but no `commitmentLabel` is now refused.
  - Recommendation: before publishing, freeze the current schema as a version, and from then on make every change a new version, Cargo-style.
  - For the "unpublished" interim, either bump at each change, or call it `0` / "unstable" explicitly.
- **A missing `version` must not default to "current".**
  - Cargo and Poetry default a missing marker to the *oldest* format.
  - cakeys defaults to the newest, so once v2 exists an unmarked v1 lock would be parsed as v2.
  - Recommendation: make `version` required (no serde default). An absent lock file can still start at the current version.
- **The unknown-field policy needs one written rule.** Today it is a side effect of serde attributes. Options from prior art:
  - **SLSA/TUF strict.** Reject unknown fields in compared sections. If kept, TUF says preserve them when re-serializing.
  - **PEP 751 major/minor.** A `version = "1.1"` reader warns on unknown keys in provenance sections and errors on an unknown major.
  - Recommended for cakeys:
    - unknown fields in identity or compared sections (`objects.*`, compared realisation fields): **refuse**;
    - unknown scheme names in `ids`: **warn, never count as proof** (current behaviour; matches SRI and in-toto "ignore unknown");
    - unknown fields in a dedicated provenance sub-table: **preserve and warn**.
  - This requires moving provenance into its own table (Q5).
- **Migration needs a rule and a verb.** No cakeys code migrates lock versions. Cargo's rule (keep the found version, upgrade only on an explicit
  write) is a good model. Under `--update-lock` cakeys writes whatever it parsed, so the rule is a policy decision to make before v2.

### Gaps

- The Cargo version history above could not be confirmed from a fetched primary page (docs URLs returned 404). It rests on search summaries of the ResolveVersion docs and Cargo source.
- I found no documented `MODULE.bazel.lock` `lockFileVersion` migration policy.
- I did not check pnpm's `lockfileVersion` rules (e.g. `'6.0'` → `'9.0'`).

## Q5. Provenance vs identity: which fields are compared and which are informational?

### Takeaway

The clearest prior art (SLSA, PEP 751, Bazel) puts identity-determining inputs and execution metadata in **different
structures**. Informational data is explicitly marked as unable to affect the outcome. Tool-version fields in the
lock itself are a known source of churn. cakeys has the right intent but mixes the classes inside one realisation table.
It also decides the class field by field in code, not by schema.

### Cited Findings

- **SLSA keeps inputs and execution apart**: `buildDefinition` "describes all of the inputs to the build", while `runDetails` holds "Details specific to this particular execution". — [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- **PEP 751**:
  - `created-by` records "the name of the tool used to create the lock file". It is not referenced by the installation steps.
  - `[tool]` data "MUST NOT affect installation".
  - Dependency edges are "purely informational for auditing purposes".
  — [PEP 751](https://peps.python.org/pep-0751/)
- **Bazel**:
  - `moduleExtensionMetadata` "contains metadata provided by the extension" and "powers the `bazel mod tidy` command". It is not a resolution input.
  - The separate hidden lockfile under `output_base` is "only used as a performance optimization" and has an unspecified format.
  — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **Bundler's `BUNDLED WITH`** (the tool version in the lock) "causes conflicts across developers". — [Nesbitt 2026](https://nesbitt.io/2026/01/17/lockfile-format-design-and-tradeoffs.html)
- **Nix flake.lock**: if `locked` and the fetcher both return `lastModified`, "they must have the same value". So even a timestamp-like field is *compared* once it is in `locked`. — [nix flake manual](https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-flake)
- **cakeys classification today** (from `ops.rs` `reconcile` / `warn_provenance` and DESIGN §4.2):
  - **Compared, failing**:
    - `objects.*.ids`;
    - `objects.*.type` (exit 14, even under `--update-lock`);
    - `specDigest` (exit 14 unless `--update-lock`);
    - `mode` (a downgrade is exit 14).
  - **Warning**:
    - a different `provider`;
    - a different module build identity (`description`, `manufacturer`, `version`, `cryptoki`);
    - a different `token`, per DESIGN §4.2;
    - a locked scheme unknown to this cakeys.
  - **Note**: a different `module.path`; a different `cakeysVersion`.
  - **Not compared on verify at all, only diffed when `--update-lock` decides whether to rewrite**:
    - `uri`;
    - `publicOnly`;
    - `mechanisms`.

    `publicOnly` is read from `keys.toml`, not from the lock. But validation forbids `publicOnly` together with policy attributes or
    `autoCreate`: "publicOnly cannot verify private-key policy attributes; leave attributes empty" (`ops.rs` lines 71–79).
    So turning it on normally also changes `attributes`, and therefore `specDigest`, and verify fails with exit 14 as intended.
    The flip false→true is silent only for a spec whose `attributes` were already empty. It then drops the check that the
    private half is present. The flip true→false only strengthens the check.
  - **Consumed downstream although never verified**: `mechanisms` feeds `functions.<token>` in the Nix library (`nix/lib.nix` lines 67–73). `module` and `token` are exposed as `module`/`tokenInfo`.
  — `crates/pkcs11/src/ops.rs`; `nix/lib.nix`; `docs/DESIGN.md` §4.2
- **`cakeysVersion` causes churn.** `cakeys_version` and `module` (including the `/nix/store/…` `path`) are in the `differs` test. Any `realise --update-lock` after a cakeys or nixpkgs bump therefore rewrites every realisation it touches. The example lock pins `path = "/nix/store/iffdlp93…-yubico-piv-tool-2.7.3/lib/libykcs11.so"`. — `crates/pkcs11/src/ops.rs` `reconcile`; `examples/yubikey-secureboot.lock`

### Inferences

- **Make the compare/provenance split a schema property, not a code property.** For example:
  - `[realisations.<spec>.<token>]` holds the compared fields: `object`, `specDigest`, `mode`, `publicOnly`, `uri`, or a locator digest.
  - `[realisations.<spec>.<token>.provenance]` holds the informational fields: `module`, `token`, `provider`, `cakeysVersion`, `mechanisms`.
  - That gives a reader a mechanical rule, and supports a PEP-751-style "disposable" guarantee: deleting `provenance` must never change any verify outcome.
- **`mechanisms` is the one field that breaks the split.** It is observational, yet it changes Nix evaluation (`functions`), so it is neither identity nor disposable.
  - Either declare it a **cached observation**: an input to Nix eval, refreshed only by `--update-lock`, never compared, and documented as such.
  - Or move it out of the lock into an eval-time `caps` artefact.
- **Volatile provenance causes needless churn.** `module.path` and `cakeysVersion` act like Bundler's `BUNDLED WITH`. Options:
  - drop `path` from the lock (DESIGN already says only a note);
  - or exclude provenance-only differences from the `differs` test, so provenance is refreshed only when a compared field changes or on explicit request.
- **`publicOnly` and the locator (`uri`) affect *what is proven*,** so they belong to the compared class:
  - `publicOnly` turns off private-half presence and policy checks;
  - the locator decides which object is examined.

  Today two `keys.toml` edits break DESIGN §10's "A changed `keys.toml` is reported as such":
  - moving the locator to different material produces an *unexplained* hash mismatch;
  - flipping `publicOnly` on an attribute-less spec silently drops the private-half presence check.

  `publicOnly` with attributes is already caught through `specDigest`.

### Gaps

- I found no prior-art lock that records hardware-token identity (serial or firmware). The nearest analogues are Bazel's OS/arch keys and PEP 751 `environments`. Whether `token.serial` should be compared (binding a realisation to one physical token) or remain provenance is a cakeys design decision with no direct precedent.

## Q6. Determinism, merge and multi-writer behaviour, `--locked`/`--frozen` semantics, and implications for the cakeys lock

### Takeaway

Mature tools give the lock deterministic output (sorted, schema-ordered, line-friendly), flat entries that merge, and a
three-way verification switch: update, check-only, use-as-is. They also say which sections are union-mergeable and which must
be regenerated. cakeys is already deterministic, flat and FOD-like, and `verify`/`check` act as `--locked`. Its remaining
gaps are in versioning, field classification, the object binding of realisations, and concurrency.

### Cited Findings

- **uv**:
  - With `--locked`, "If the lockfile is not up-to-date, uv will raise an error instead of updating the lockfile".
  - `--frozen` uses "the lockfile without checking if it is up-to-date".
  - Up-to-date means it "matches the project metadata". A new upstream release does not make it outdated.
  - `uv lock --check` "is equivalent to the `--locked` flag".
  — [uv docs, Locking and syncing](https://docs.astral.sh/uv/concepts/projects/sync/)
- **Bazel `--lockfile_mode`**:
  - `update` (default) adds missing information.
  - `refresh` also refreshes mutable data.
  - `error` fails on missing or out-of-date data, and "never changes the lockfile".
  - `off`: "neither checked nor updated".
  — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **Bazel merging**:
  - Bazel ships a git merge driver (`MODULE.bazel.lock merge=bazel-lockfile-merge`, needs jq ≥ 1.5).
  - Manual conflicts "can be safely resolved by keeping all the entries from both sides" only for `registryFileHashes` and `selectedYankedVersions`.
  - "Other types of merge conflicts should not be resolved manually." Instead, restore the file, fix `MODULE.bazel`, and rerun `bazel mod deps`.
  — [Bazel lockfile docs](https://bazel.build/external/lockfile)
- **Go**:
  - A hash that differs from `go.sum` is a security error: the download is deleted, not cached.
  - A missing hash is verified against the checksum database, a Trillian-backed transparent log (Merkle tree), then appended.
  - Inclusion and consistency proofs run "before adding new `go.sum` lines".
  - `go.sum` "may also contain hashes for module versions that aren't needed anymore"; `go mod tidy` adds missing and removes unnecessary hashes.
  — [Go Modules Reference](https://go.dev/ref/mod#go-sum-files)
- **Go's sumdb threat model**: it "makes untrusted proxies possible since they can't serve the wrong code without it going unnoticed", and "ensures that the bits associated with a specific version do not change from one day to the next, even if the module's author subsequently alters the tags". — [Go Modules Reference, Checksum database](https://go.dev/ref/mod#checksum-database)
- **TUF**:
  - Signatures are over the canonical form, using a "canonical JSON" subdialect.
  - Clients "MUST NOT replace a metadata file with a version number less than the one currently trusted" (rollback protection) and "MUST NOT trust an expired file".
  — [TUF specification](https://theupdateframework.github.io/specification/latest/)
- **Determinism and format**:
  - PEP 751: tools "SHOULD write their lock files in a consistent way to minimize noise in diff output", with consistently sorted arrays and key order. — [PEP 751](https://peps.python.org/pep-0751/)
  - Nesbitt:
    - "Sort entries deterministically", as Cargo.lock does.
    - TOML (Cargo, Poetry, uv) is merge-friendlier than JSON (npm, bun), where "adding an entry modifies two lines".
    - Nested structures make two branches conflict "even when both branches resolved to the same version".
    - pnpm's v6 format redesign cited merge-conflict reduction.
    - Line formats like go.sum "diff best of all but can't represent structured metadata".
    — [Nesbitt 2026](https://nesbitt.io/2026/01/17/lockfile-format-design-and-tradeoffs.html)
- **npm's hidden lockfile** (`node_modules/.package-lock.json`) is used only when every referenced folder exists, no unlisted folder exists, and its mtime is at least as recent as all of them. "If another CLI mutates the tree in any way, this will be detected, and the hidden lockfile will be ignored." — [npm package-lock.json docs](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json)
- **Poetry** (search summary of source code): `[metadata].content-hash` is a sha256 of the relevant `pyproject.toml` content as sorted JSON. A missing or different hash makes the lock stale. — [poetry locker.py](https://github-redirect.dependabot.com/python-poetry/poetry/blob/6dc4c516cf4228b68d56c532b8b7db15dcf83413/src/poetry/packages/locker.py) **(search summary)**
- **cakeys today**:
  - **Serialization**: `toml::to_string_pretty` over `BTreeMap`s. Mechanisms are sorted (`token.rs` `mechanism_names`).
  - **Atomic writes**: temporary file, then rename. There is no locking (finding M3).
  - **`--update-lock` "only fills gaps"**: it never overwrites a locked ID.
  - **No GC** (D3).
  - **Verbs**: `verify`/`check` never write; `realise --update-lock` writes.
  - **Spec digest**: SHA-256 of canonical JSON `{"v":1,"type":…,"attributes":…}`. It does **not** include the object name, the locator, `publicOnly`, `autoCreate`, `identity.allow` or the token's `tokenLabel`.
  — `crates/core/src/config.rs` `save_lock`; `crates/core/src/id.rs` `spec_digest`; `docs/DESIGN.md` §3.5, §4.2, §5; `docs/REVIEW-2026-11-11.md` M3, D3

### Inferences

#### Verification semantics mapped to cakeys

- **`verify` / `check`** ≈ uv `--locked`, Bazel `error`, and the Nix FOD check. That is correct.
- **`realise --update-lock`** ≈ Bazel `update`, but with Go-style append-only IDs. That is correct: "only fills gaps" is the FOD and go.sum property.
- **There is no `--frozen` equivalent (use without checking), and none should be added.** The tool's whole premise is the check.
- **There is no `tidy`/GC (D3).** Go and Bazel both drop entries no longer needed. A `gc` verb that prints, then applies, matches `go mod tidy`.

#### Merge and multi-writer

- **cakeys's TOML layout is already the merge-friendly kind.** It has flat per-object and per-(spec, token) tables, sorted keys and one-line values.
  The 27-line `mechanisms` arrays and volatile provenance are what will conflict in practice.
- **Declare a merge rule per section, Bazel-style:**
  - **`realisations.<spec>.<token>`**: union-safe across different (spec, token) keys. Same key on both sides: regenerate.
  - **`objects.<name>.ids`**: union-safe per scheme only if no scheme has two different values. A conflicting value is a real identity conflict; never auto-resolve it.
  - **`objects.<name>.type` / `commitmentLabel`**: must be identical on both sides, otherwise refuse.
  - **`version`**: must be identical.

  A small `cakeys lock merge` (or a git merge driver) could enforce this mechanically.
- **Concurrent writers.** M3 (an advisory `flock` around read-modify-write) is the direct fix. Atomic rename only prevents torn
  files. I found no lockfile tool that documents cross-process locking in these sources (see Gaps).

#### Join and split

- **Prior art splits locks by scope.**
  - Go keeps a workspace-level `go.work.sum` that "keeps track of hashes used by the workspace that are not in collective
    workspace modules' `go.sum` files". That is a join file layered over the per-module locks — [Go Modules Reference](https://go.dev/ref/mod).
  - Bazel's lockfile "includes only dependencies used in the current build invocation". It keeps a separate hidden lockfile under
    `output_base` that is "only used as a performance optimization" — [Bazel lockfile docs](https://bazel.build/external/lockfile).
- **Option for cakeys (alongside G9, not instead of it):**
  - Keep `objects.*` (type, commitment label, IDs) as one shared, global identity table.
  - Split realisations, which are per token and per host, out:
    - either as a per-token sub-table convention;
    - or as separate files (e.g. `keys.lock` for identity plus `keys.<token>.lock` for realisations and provenance).
  - Two writers on different tokens would then touch different files. That removes most of the M3 race and most of the
    `mechanisms`/provenance merge churn.
  - Only appends to `objects.*.ids` remain shared. They are append-only and union-mergeable per scheme.
  - Cost: verification must join the files, and a missing realisation file must be "not realised here", never "unverified".

#### Determinism decision to record

- **cakeys does not need a canonical byte form for the lock itself** as long as nothing hashes or signs the lock. Byte-level formatting
  depends on the `toml` crate version, which is noise rather than semantics.
- **Record this decision in DESIGN §10.** If lock signing (TUF/Sigstore-style) or a lock-level digest is ever added, a canonical
  form becomes mandatory, as TUF requires canonical JSON for signatures. The *spec digest* already has an explicit canonical form,
  so that part is fine.

#### Already aligned with prior art (keep)

- **New computation means a new scheme name.** This matches go.sum's `h1`→`h2` and Nix `outputHashMode`.
- **The SRI `sha256-` prefix on every ID.** This matches Nix and SRI.
- **A versioned digest preimage** (`"v":1` in the spec-digest JSON).
- **Unknown scheme names are ignored with a warning and never count as proof.** This matches SRI and in-toto "ignore unknown".
- **IDs are append-only, and a mismatch fails.** This matches go.sum and the FOD model.
- **The object type is recorded and compared**, and so is the commitment label. These are the computation parameters, like Nix's `outputHashMode`/`Algo`.
- **Per-entry input digest (`specDigest`) instead of a whole-manifest hash.** This matches Bazel `usagesDigest` and avoids Poetry-style whole-lock invalidation.
- **The lock holds digests of token outputs, never raw outputs.**
- **Sorted maps and sorted mechanisms; atomic rename.**

#### Gaps in the current cakeys lock (confirmed against code at `8889898`)

1. **G1 — `version = 1` is underdefined.** The schema changed in place at least twice (`90d5353`, `8889898`), and an absent
   `version` defaults to *current*. Fix:
   - make `version` required;
   - freeze a version per schema;
   - define the reader rule: refuse an unknown major; for minor, decide warn vs refuse (see G5);
   - define the writer rule: keep the version found, like Cargo.
2. **G2 — A realisation does not name its object.** `specDigest` hashes `type` and `attributes` only. Retargeting
   `specs.<s>.object` to a different object *of the same type* leaves `specDigest` unchanged. `reconcile` then compares the
   live material against the other object's IDs, and reports an unexplained hash mismatch (exit 10), or "first use" if the new object has no IDs.
   Fix: record `object = "<name>"` in each realisation and compare it, with exit 14 "spec retargeted". Alternatively, include the object name in a v2 spec digest.
3. **G3 — Locator and `publicOnly` changes go undetected.** `uri` and `publicOnly` are recorded but only diffed under `--update-lock`; verify never compares them.
   - A locator edit that points at different material leads to an unexplained hash mismatch, not "keys.toml changed". If it points at the same material, it passes, which is correct by design: locators are not identity.
   - A `publicOnly` false→true flip is silent only for attribute-less specs, because validation forbids `publicOnly` with attributes, so the usual case changes `specDigest`. In that silent case it drops the private-half presence check.

   Fix: compare both as "lock out of date" (exit 14, re-record with `--update-lock`), like `specDigest`. Or define a
   realisation-input digest over the locator, `publicOnly`, `identity.allow` and the token's `tokenLabel`, and declare `autoCreate`
   explicitly out of scope, since it only gates creation.
4. **G4 — The lock does not record which realisation established each ID.**
   - `objects.<n>.ids` is a union across tokens. The lock alone cannot show which (spec, token) computed which scheme, so it cannot prove the "linked only through a shared scheme" rule (DESIGN §3.5) after the fact.
   - RFC 62 realisations and flake.lock nodes record their edges.
   - Fix: per realisation, record `schemes = ["pubkeyhash", …]` (names only, since values are in `objects`). Then the lock is self-contained for audit, and per-token re-verification knows what to expect.
5. **G5 — There is no written unknown-field policy.** `deny_unknown_fields` everywhere, plus exact version match, versus tolerated unknown schemes. Fix: the policy in Q4's
   Inferences, which needs the provenance sub-table (G6).
6. **G6 — The compare/provenance split lives in code, not in the schema.** `module`, `token`, `provider`, `cakeysVersion` and `mechanisms` sit next to
   compared fields. Fix:
   - a `provenance` sub-table guaranteed disposable (PEP 751 `[tool]` semantics);
   - `mechanisms` either declared a cached observation or moved out;
   - provenance-only differences no longer trigger a rewrite;
   - consider dropping `module.path`, which is a `/nix/store` path and churns on every nixpkgs bump.
7. **G7 — ID values are not validated.** Any string is accepted in `ids`, `specDigest` and `commitmentLabel`. Fix: parse SRI with an allowed algorithm
   set, and the label charset, in `Lock::validate`. A malformed lock is then exit 17, not exit 10.
8. **G8 — There is no scheme-strength policy.** Nothing says a scheme is deprecated or insufficient alone. Fix: a frozen per-scheme table (strength, or whether it is sufficient alone), pinned by a known-answer test, analogous to in-toto's "only accept algorithms they consider secure".
9. **G9 — Concurrency and GC.** These are M3 and D3. Add `flock` and a `gc` verb (print, then `--apply`), and write down the per-section merge rule above.
10. **G10 — Premises are not listed as frozen.** Two things should be added to DESIGN §10's frozen list:
    - the provider fix-up rule (§6.2), which is what makes `provider` and `module` legitimately provenance;
    - the RustCrypto canonical re-encoding (§3.2), which pins the `pubkeyhash` preimage. The KATs pin it, but the premise is not stated.

    This follows SLSA's warning that "internal" parameters "MAY be necessary for reproducing".

#### Decide-against list (deliberately not adopted, with reason)

- **A whole-`keys.toml` content hash** (Poetry `content-hash`): it invalidates the whole lock on any edit and conflicts on every merge. Use per-entry digests (G2, G3).
- **A transparency log or signatures** (Go sumdb, TUF, Sigstore): no public registry and no untrusted proxy exists. The token is the source of truth, rechecked on each use. Revisit only if locks are distributed to third parties.
- **`--frozen`, i.e. use without verifying**: it contradicts the purpose.
- **ANY-match semantics** (in-toto): weaker than cakeys's "all computed must agree".
- **A canonical byte form for the lock**: not needed until the lock is hashed or signed. Record this as a decision.

### Gaps

- **Sigstore/Rekor** was not fetched. Its relevance is limited to lock signing or transparency, which is on the decide-against list.
- **npm `npm ci`** (fails on a package.json/lock mismatch) and npm's automatic git-conflict resolution are not documented on the package-lock page fetched, so they are not cited.
- **Nix flake CLI flags** (`--no-update-lock-file`, `--no-write-lock-file`, `--recreate-lock-file`) are not on the flake page fetched, so they are not cited.
- **Cross-process locking.** I found no source describing how Cargo, uv or Bazel lock their lock files between concurrent processes. The `flock` recommendation rests on the cakeys review (M3), not on prior art.
- **Yarn Berry `__metadata.cacheKey` and pnpm `settings`** (lock-level parameters that invalidate entries) were not covered by the sources fetched.
- **Cargo `--locked` / `--frozen` / `--offline`** semantics were not fetched (the Cargo docs pages 404'd), so they are not cited. uv and Bazel stand in for that comparison.
