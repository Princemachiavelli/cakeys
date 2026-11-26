# cakeys, caprobe and camigrate built with crane: the dependencies once per Cargo.lock
# (`buildDepsOnly`), reused by this build, its tests, clippy and their reruns, so a source change
# rebuilds only the workspace's own crates. `nix flake check` uses it (checks.nix), and
# packages.cakeys is it without the check phase (`unchecked`). The source, outputs, patches,
# features and test environment are in nix/package-common.nix.
{
  lib,
  callPackage,
  craneLib,
  rustc,
  stdenv,
  cargo-mutants,
  cargo-nextest,
  python3,
  quint,
  # The toolchain at Cargo.toml's rust-version (pkgs.nix), for `msrv`.
  msrvToolchain,
  # Kani (nix/kani.nix), for `kani`; x86_64-linux only, null elsewhere.
  kani ? null,
  # See nix/package-common.nix.
  withTpm2 ? null,
}:
let
  common = callPackage ./package-common.nix (
    lib.optionalAttrs (withTpm2 != null) { inherit withTpm2; }
  );
  features = "--features ${lib.concatStringsSep "," common.features}";
  scope = lib.escapeShellArgs (
    common.cargoScope ++ lib.optional common.noDefaultFeatures "--no-default-features"
  );

  # The cryptoki patches (nix/package-common.nix), on crane's checkout of the rust-cryptoki
  # repository the lock names (a git source: the patches are relative to its cryptoki/ crate).
  cargoVendorDir = craneLib.vendorCargoDeps {
    inherit (common.args) src;
    overrideVendorGitCheckout =
      ps: drv:
      if lib.any (p: p.name == "cryptoki" && p.version == common.cryptoki.version) ps then
        drv.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ common.cryptoki.patches;
          patchFlags = [
            "-p1"
            "-d"
            "cryptoki"
          ];
        })
      else
        drv;
  };

  # cargo's target runner, as an environment variable: what wraps every test process.
  runner = "CARGO_TARGET_${stdenv.hostPlatform.rust.cargoEnvVarTarget}_RUNNER";

  # What the dependencies' build and every build on it share. Unit tests live in every crate,
  # not just the tools (the default members).
  base = {
    inherit (common.args)
      pname
      version
      src
      nativeBuildInputs
      buildInputs
      ;
    inherit cargoVendorDir;
    # What nixpkgs' Rust builder sets: libsqlite3-sys links the system sqlite (buildInputs).
    LIBSQLITE3_SYS_USE_PKG_CONFIG = 1;
    strictDeps = true;
    cargoExtraArgs = "--locked ${scope} ${features}";
  };
  cargoArtifacts = craneLib.buildDepsOnly base;

  # The check phase's test command, narrowed by a nextest filter (the spec-coverage report).
  cargoTestCommandFor =
    filter:
    "cargo nextest run \${CARGO_PROFILE:+--cargo-profile $CARGO_PROFILE} ${base.cargoExtraArgs}"
    + " --no-fail-fast --no-tests=fail --show-progress none -E ${lib.escapeShellArg filter}";

  # What a nextest run ran and skipped, per test binary (nix/test-count.py): it fails when a
  # binary the cargo arguments build ran other tests than its source has (one lost, or a whole
  # binary). `partial` for a run a filter narrows: the counts alone.
  testCount =
    partial:
    "${python3}/bin/python3 -I ${./test-count.py} . --junit \${CARGO_TARGET_DIR:-target}/nextest/default/junit.xml"
    + " --skips $CAKEYS_SKIP_LOG ${lib.optionalString partial "--partial"} -- ${base.cargoExtraArgs}";

  # Without the `tpm2` and `ykcs11` features: the tools build without tpm2-tss and sqlite (their
  # own dependency set).
  minimal = base // {
    pname = "cakeys-minimal";
    buildInputs = [ ];
    cargoExtraArgs = "--locked --no-default-features --features cakeys/patched-cryptoki,caprobe/patched-cryptoki,camigrate/patched-cryptoki";
    doCheck = false;
  };

  # cargo-mutants: each mutant is one small change to the code (a function body replaced, an
  # operator flipped), and one the tests still pass with is a place they do not check. Not a
  # check: it takes as long as its scope is wide and always succeeds once the unmutated tests
  # pass. The report is the output, one directory per scope: missed.txt (what no test caught),
  # caught.txt, timeout.txt, unviable.txt and outcomes.json.
  #
  # `scopes` is a list of { package, files, workspace ? false, re ? null, name ? package }, `re`
  # keeping only the mutants whose name matches (`--re`, e.g. one function), `name` the scope's
  # directory in the report (two scopes of one package need two). A package's mutants meet that
  # package's own tests: seconds each, so the unit tier runs in minutes. With `workspace` they
  # meet every crate's tests (a minute each: the whole workspace is rebuilt per mutant). With
  # `tokens`, every crate's tests run under cargo-nextest with a token set per test (as the check
  # phase runs them), so the integration suites can catch mutants too: one mutant at a time, its
  # tests in parallel, stopping at the first that fails; minutes for a mutant no test catches.
  # They run in place, so each scope after the first starts from the last one's build, not from
  # nothing (a copy of the tree builds every dependency again).
  #
  # For the gate (nix/mutants-baseline.py; .github/workflows/mutants.yml):
  # - `inDiff`, a diff (a path): only the mutants in the lines it touches (`--in-diff`).
  # - `shard`, "k/n" with k from 0: the k-th of n parts of the mutants (`--shard`), one per job.
  # - `iterate`, earlier reports of the same scopes (a path or a list): the mutants they caught
  #   or found unviable are skipped (`--iterate`), so the token run tests only what the package's
  #   own tests left.
  # - `testFilter`, a nextest filter expression for the token runs.
  # - `timeout`, seconds a mutant's tests may take: a token run's would otherwise be a multiple of
  #   the unmutated suite's, itself minutes. null: cargo-mutants' own, from the unmutated run.
  # Every scope's directory also holds all-mutants.json, the scope's every mutant whatever the
  # diff, shard or earlier report left out (`--list`): the gate numbers identical keys with it.
  mutants =
    {
      scopes,
      tokens ? false,
      jobs ? 6,
      inDiff ? null,
      shard ? null,
      iterate ? null,
      testFilter ? null,
      timeout ? if tokens then 600 else null,
    }:
    let
      run =
        {
          package,
          files,
          workspace ? false,
          re ? null,
          name ? package,
        }:
        let
          # What selects the scope's mutants: the run's and the full list's.
          select = "--package ${package} ${
            lib.concatMapStringsSep " " (f: "--file ${lib.escapeShellArg f}") files
          } ${lib.optionalString (re != null) "--re ${lib.escapeShellArg re}"}";
          # The tools' features: a run that tests every crate takes them all; one package alone
          # takes its own (camigrate's and caprobe's tests hold their feature to the patched
          # binding), not the other tools'.
          own = lib.filter (f: lib.hasPrefix "${package}/" f) common.features;
        in
        ''
          code=0
          report="$TMPDIR/report-${name}"
          ${lib.optionalString (iterate != null) ''
            mkdir -p "$report/mutants.out"
            for earlier in ${lib.escapeShellArgs (map (r: "${r}") (lib.toList iterate))}; do
              [ -d "$earlier/${name}" ] || { echo "mutants: no ${name} in $earlier" >&2; exit 1; }
              for f in caught.txt unviable.txt previously_caught.txt; do
                if [ -f "$earlier/${name}/$f" ]; then cat "$earlier/${name}/$f" >>"$report/mutants.out/caught.txt"; fi
              done
            done
          ''}
          cargo mutants ${select} ${lib.optionalString (workspace || tokens) "--test-workspace=true"} \
            --no-shuffle --colors never ${if tokens then "--in-place" else "--jobs ${toString jobs}"} \
            ${lib.optionalString (inDiff != null) "--in-diff ${inDiff}"} \
            ${lib.optionalString (shard != null) "--shard ${lib.escapeShellArg shard}"} \
            ${lib.optionalString (iterate != null) "--iterate"} \
            ${lib.optionalString (timeout != null) "--timeout ${toString timeout}"} \
            ${
              lib.optionalString (workspace || tokens || own != [ ]) (
                lib.optionalString common.noDefaultFeatures "--no-default-features "
                + "--features ${lib.concatStringsSep "," (if workspace || tokens then common.features else own)}"
              )
            } \
            --cargo-arg=--locked --output "$report" \
            ${
              # cargo-mutants builds and tests only the mutated package whatever --test-workspace
              # says, and the tests run the tools' binaries: every cargo call selects the three
              # tools too, which also makes their features valid for a library's mutants.
              lib.optionalString tokens (
                "--test-tool nextest "
                + lib.concatMapStringsSep " " (p: "--cargo-arg=--package=${p}") [
                  "cakeys"
                  "caprobe"
                  "camigrate"
                ]
              )
            } ${
              lib.optionalString (testFilter != null) (
                lib.escapeShellArgs [
                  "--cargo-test-arg=-E"
                  "--cargo-test-arg=${testFilter}"
                ]
              )
            } || code=$?
          # 0: every mutant caught; 2: some missed; 3: some timed out. Those are the report.
          # Anything else (the unmutated tests failing, a bad invocation) fails the build.
          case $code in 0 | 2 | 3) ;; *) exit $code ;; esac
          mkdir -p $out/${name}
          # No mutant in the diff, or none the earlier reports left: cargo-mutants writes nothing.
          if [ -d "$report/mutants.out" ] && [ -f "$report/mutants.out/missed.txt" ]; then
            cp -r "$report"/mutants.out/* $out/${name}/
          else
            touch $out/${name}/{caught,missed,timeout,unviable}.txt
          fi
          cargo mutants ${select} --list --json \
            | ${python3}/bin/python3 -I -c 'import json, sys; json.dump([{k: v for k, v in m.items() if k != "diff"} for m in json.load(sys.stdin)], sys.stdout)' \
            >$out/${name}/all-mutants.json
        '';
    in
    craneLib.mkCargoDerivation (
      base
      // {
        pnameSuffix = "-mutants";
        # Each job builds its own copy of the tree: nothing to reuse.
        cargoArtifacts = null;
        doInstallCargoArtifacts = false;
        nativeBuildInputs =
          base.nativeBuildInputs
          # core's own tests include tests/lock_mbt.rs, which runs quint.
          ++ [
            cargo-mutants
            quint
          ]
          ++ lib.optionals tokens (common.args.nativeCheckInputs ++ [ cargo-nextest ]);
      }
      // lib.optionalAttrs tokens {
        # A token set per test, as the check phase and the coverage report run them.
        ${runner} = "bash ${./test-tokens.sh}";
      }
      // {
        preBuild = lib.optionalString tokens common.args.preCheck;
        buildPhaseCargoCommand = lib.concatMapStrings run scopes;
        installPhaseCommand = "";
      }
    );

  # The gate's two tiers, `unit` and `tokens`, as nix/mutants-scopes.toml lists them
  # (docs/archive/REVIEW-2026-11-24/phase2-3-design.md §5.1). A `unit` scope's mutants meet only
  # their own package's tests. A `tokens` scope holds code that only the token suites reach. The
  # file's `left-out` table, the files that no tier mutates, is for checks.mutants-scopes only. A
  # scope whose package this build leaves out is dropped here, because cargo cannot build it:
  # `common.cargoScope` excludes cakeys-tpm2-pkcs11 where the tpm2 feature is off, as on darwin.
  mutantsScopes =
    let
      listed = builtins.fromTOML (builtins.readFile ./mutants-scopes.toml);
      built = lib.filter (s: !(lib.elem s.package common.cargoScope));
    in
    {
      unit = built listed.unit;
      tokens = built listed.tokens;
    };

  # One tier of the gate, whole or over a diff, sharded or not:
  # - "unit": its scopes against their packages' own tests;
  # - "tokens-first": the token tier's scopes against their packages' own tests, the first pass;
  # - "tokens": what the first pass left (`iterate`, the first pass over the same diff by
  #   default), against every crate's tests under the token suites. Not the reference suite again
  #   on kryoptic and through p11-kit, which would double the time a mutant takes for little more,
  #   nor the lints over the test sources (surface, harness); what only those would catch shows
  #   as a survivor.
  mutantsTier =
    {
      tier,
      diff ? null,
      shard ? null,
      iterate ?
        if tier == "tokens" then
          mutantsTier {
            inherit diff;
            tier = "tokens-first";
          }
        else
          null,
    }:
    mutants (
      {
        inherit shard iterate;
        inDiff = diff;
      }
      // {
        unit.scopes = mutantsScopes.unit;
        tokens-first.scopes = mutantsScopes.tokens;
        tokens = {
          scopes = mutantsScopes.tokens;
          tokens = true;
          testFilter = "not (binary(kryoptic) | binary(p11kit) | binary(surface) | binary(harness))";
        };
      }
      .${tier}
    );
in
craneLib.buildPackage (
  common.args
  // base
  // {
    inherit cargoArtifacts;
    # cargo-nextest: one process per test, each through nix/test-tokens.sh (cargo's target
    # runner), which gives it a token set of its own: the suites run in parallel, and no test
    # sees what another left on a token. The coverage report runs them the same way, as does
    # the mutation report with the token suites.
    nativeBuildInputs = base.nativeBuildInputs ++ [ cargo-nextest ];
    ${runner} = "bash ${./test-tokens.sh}";
    cargoTestCommand = "cargo nextest run \${CARGO_PROFILE:+--cargo-profile $CARGO_PROFILE}";
    # No progress bar: the build log is not a terminal, whatever nextest sees. A run with no
    # test fails (it is nextest's default, said here).
    cargoTestExtraArgs = "--no-fail-fast --no-tests=fail --show-progress none";
    # Each test binary's run and skipped counts in the log, and a failure where a binary ran
    # other tests than its source has (review 2026-11-24 C-11; docs/DEVELOPMENT.md "Testing").
    postCheck = lib.optionalString common.canCheck (testCount false);
    # The check phase holds spec-coverage/cakeys.toml to the baseline and manual.toml from its
    # own `used` rows; regenerating them from a traced run is the spec-coverage report below.
    passthru = {
      # What packages.cakeys ships (pkgs.nix; the NixOS module's default and the apps too): this
      # build without its check phase, on the same dependency artifacts, so what users run is what
      # every check and CI job builds, and its first use runs no token suite (review 2026-11-23
      # C-8: it was a second, regular buildRustPackage build that nothing built).
      unchecked = craneLib.buildPackage (
        common.args
        // base
        // {
          inherit cargoArtifacts;
          doCheck = false;
          # The cryptoki version and patches, and the features that need them, for builds outside
          # Nix: scripts/local-tests.sh reads them with `nix eval --json .#cakeys.patchedCryptoki`,
          # so its lists are these, not a copy. Each patch interpolated: a store path of its own,
          # which `nix eval` copies there, where a path value would print as a place in the
          # flake's source that need not exist on disk.
          passthru.patchedCryptoki = {
            inherit (common.cryptoki) version;
            patches = map (p: "${p}") common.cryptoki.patches;
            inherit (common) features;
          };
        }
      );
      # Clippy with -D warnings over every target: the workspace lints (Cargo.toml
      # [workspace.lints]: unsafe_code deny, clippy::pedantic with one blanket allow) travel with
      # every build, editor and this check.
      clippy = craneLib.cargoClippy (
        base
        // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        }
      );
      # rustdoc over every crate, private items included, warnings as errors: a doc link that no
      # longer resolves fails here. (Evidence tags in doc comments are written `\[run\]`.)
      doc = craneLib.cargoDoc (
        base
        // {
          inherit cargoArtifacts;
          cargoDocExtraArgs = "--no-deps --document-private-items";
          RUSTDOCFLAGS = "-D warnings";
        }
      );
      # Every target checked with the toolchain at Cargo.toml's rust-version, the dependencies
      # built with it too: the minimum the workspace states is one it builds with.
      msrv =
        let
          craneMsrv = craneLib.overrideToolchain (_: msrvToolchain);
          args = base // {
            pnameSuffix = "-msrv";
          };
        in
        craneMsrv.mkCargoDerivation (
          args
          // {
            cargoArtifacts = craneMsrv.buildDepsOnly args;
            buildPhaseCargoCommand = "cargo check --release --all-targets ${base.cargoExtraArgs}";
            doInstallCargoArtifacts = false;
            installPhaseCommand = "mkdir -p $out";
          }
        );
      # The Kani proofs in cakeys_core::fuzzing and cakeys_tpm2_pkcs11::fuzzing (docs/OPEN.md, "Kani
      # and fuzzing"), each for every input up to the bound it sets; fix_ec_point's, at 5.7 GB,
      # is the largest. kani-compiler builds the crates and their dependencies itself, from the
      # same vendored sources: no crane artifacts to reuse. Not in checks-crane-only (flake.nix).
      kani = lib.mapNullable (
        kani:
        craneLib.mkCargoDerivation (
          base
          // {
            pnameSuffix = "-kani";
            nativeBuildInputs = base.nativeBuildInputs ++ [ kani ];
            cargoArtifacts = null;
            buildPhaseCargoCommand = ''
              export HOME=$TMPDIR
              cargo kani -p cakeys-core
              cargo kani -p cakeys-tpm2-pkcs11
            '';
            doInstallCargoArtifacts = false;
            installPhaseCommand = "mkdir -p $out";
          }
        )
      ) kani;
      minimal = craneLib.buildPackage (minimal // { cargoArtifacts = craneLib.buildDepsOnly minimal; });
      # Mutation testing (docs/DEVELOPMENT.md). `mutants` is the code whose own unit and property
      # tests are its tests, no token needed: `nix build .#mutants`. `mutantsOf` takes one scope
      # ({ package, files, re ? null }) with the token suites running, for the code only they reach:
      #   nix build --impure --expr \
      #     "(builtins.getFlake \"git+file://$PWD\").packages.x86_64-linux.cakeys-crane.mutantsOf { package = \"camigrate\"; files = [ \"crates/camigrate/src/host.rs\" ]; }"
      mutants = mutants { scopes = mutantsScopes.unit; };
      mutantsOf =
        scope:
        mutants {
          scopes = [ scope ];
          tokens = true;
        };
      # The gate's runs (.github/workflows/mutants.yml, scripts/mutants-diff.sh): `mutantsTier
      # { tier; diff ? null; shard ? null; iterate ? …; }` above; `mutantsDiff` is it over a diff,
      # which a pull request's job hands in as a path:
      #   nix build --impure --expr \
      #     "(builtins.getFlake \"git+file://$PWD\").packages.x86_64-linux.cakeys-crane.mutantsDiff { diff = builtins.path { path = \"$PWD/pr.diff\"; name = \"pr.diff\"; }; tier = \"unit\"; }"
      inherit mutantsTier;
      mutantsDiff = { diff, ... }@args: mutantsTier (args // { inherit diff; });
      # Coverage as data (docs/PLAN.md A1, docs/CAPROBE.md "Coverage"): the suites again with
      # every module behind a tracing p11-fault (nix/test-tokens.sh), then spec-coverage/cakeys.toml
      # regenerated from that trace, with the tests behind each used row (coverage-report.txt). A
      # report, never a check (review 2026-11-23 D-8: it was a second full traced pass in every
      # check build, for a file only it kept current): `nix build .#spec-coverage`, then copy
      # result/cakeys.toml over spec-coverage/cakeys.toml. Traced on a pass of its own: the check
      # phase keeps every test talking to its module directly (p11-fault exports the 2.40
      # interface only).
      spec-coverage = craneLib.mkCargoDerivation (
        base
        // {
          inherit cargoArtifacts;
          pnameSuffix = "-spec-coverage";
          doInstallCargoArtifacts = false;
          nativeBuildInputs = base.nativeBuildInputs ++ common.args.nativeCheckInputs ++ [ cargo-nextest ];
          preBuild = common.args.preCheck;
          ${runner} = "bash ${./test-tokens.sh}";
          # Not traced: the coverage test, and the fault suites (nix/test-tokens.sh leaves them
          # untraced, with the other tests it names). The rewrite is accepted (CAKEYS_ACCEPT): the
          # file it replaces is this build's copy; copying the result over the committed one is
          # the change profiles/LEDGER.toml records.
          buildPhaseCargoCommand = ''
            export CAKEYS_TRACE_DIR=$TMPDIR/coverage-trace
            ${cargoTestCommandFor "not (binary(fault) | test(committed_coverage_is_generated_from_the_trace))"}
            ${testCount true}
            unset CAKEYS_TRACE_DIR
            CAKEYS_COVERAGE_TRACE=$TMPDIR/coverage-trace CAKEYS_UPDATE_COVERAGE=1 CAKEYS_ACCEPT=1 \
              ${cargoTestCommandFor "test(committed_coverage_is_generated_from_the_trace)"}
          '';
          installPhaseCommand = ''
            mkdir -p $out
            cp spec-coverage/cakeys.toml $TMPDIR/coverage-trace/coverage-report.txt $out/
          '';
        }
      );
      # Line and region coverage of the whole test run, the token suites included: the tests
      # spawn instrumented binaries, so what a CLI test reaches inside cakeys, caprobe and
      # camigrate counts. Not a check (it rebuilds everything instrumented and passes whatever
      # the numbers are): `nix build .#coverage`, then read result/summary.txt (per file),
      # result/missing.txt (the uncovered line numbers of each file) and result/html/index.html
      # (each source file with its uncovered lines and regions marked) and
      # result/uncovered-functions.txt (the functions no test entered); result/lcov.info is the
      # same data for an editor or `genhtml` (docs/DEVELOPMENT.md).
      coverage = craneLib.cargoLlvmCov (
        base
        // {
          # Nothing to reuse: the instrumented build shares no object with the plain one.
          cargoArtifacts = null;
          # The llvm-tools of this rustc's own LLVM: nixpkgs' rustc ships no llvm-tools-preview.
          LLVM_COV = "${rustc.llvmPackages.llvm}/bin/llvm-cov";
          LLVM_PROFDATA = "${rustc.llvmPackages.llvm}/bin/llvm-profdata";
          nativeBuildInputs = base.nativeBuildInputs ++ common.args.nativeCheckInputs ++ [ cargo-nextest ];
          # The token test environment, around the build phase: cargo-llvm-cov tests there, under
          # cargo-nextest with a token set per test, as the check phase does.
          preBuild = common.args.preCheck;
          ${runner} = "bash ${./test-tokens.sh}";
          cargoLlvmCovCommand = "nextest";
          cargoLlvmCovExtraArgs = "--no-report --no-fail-fast --no-tests=fail --show-progress none";
          postBuild = ''
            mkdir -p $out
            cargo llvm-cov report --release --lcov --output-path $out/lcov.info
            cargo llvm-cov report --release --summary-only > $out/summary.txt
            cargo llvm-cov report --release --show-missing-lines > $out/missing.txt
            cargo llvm-cov report --release --html --output-dir $out
            # The functions no test entered, by file. lcov counts each compiled copy of a function
            # on its own (the library's, each test binary's), so a function is uncovered only when
            # every copy of its demangled name has a zero count. (`::<_>` is a generic function's
            # uninstantiated record, not a function.)
            awk '/^SF:/ { f = substr($0, 4) } /^FNDA:/ { i = index($0, ","); print f "\t" substr($0, 6, i - 6) "\t" substr($0, i + 1) }' $out/lcov.info \
              | sed "s|^$PWD/||" | ${rustc.llvmPackages.llvm}/bin/llvm-cxxfilt \
              | awk -F '\t' '{ n[$1 "\t" $3] += $2 } END { for (k in n) if (n[k] == 0) print k }' \
              | { grep -v '::<_\(, _\)*>$' || true; } | sort > $out/uncovered-functions.txt
          '';
        }
      );
    };
  }
)
