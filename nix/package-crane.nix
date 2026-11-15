# cakeys, caprobe and camigrate built with crane: the dependencies once per Cargo.lock
# (`buildDepsOnly`), reused by this build, its tests, clippy and their reruns, so a source change
# rebuilds only the workspace's own crates. `nix flake check` uses it (checks.nix); packages.cakeys
# is the regular build (nix/package.nix). What both share is in nix/package-common.nix.
{
  lib,
  callPackage,
  craneLib,
  rustc,
  stdenv,
  cargo-mutants,
  cargo-nextest,
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

  # The cryptoki patches (nix/package-common.nix), on crane's vendored copy.
  cargoVendorDir = craneLib.vendorCargoDeps {
    inherit (common.args) src;
    overrideVendorCargoPackage =
      p: drv:
      if p.name == "cryptoki" && p.version == common.cryptoki.version then
        drv.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ common.cryptoki.patches;
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

  # Without the `tpm2` and `ykcs11` features: the tools build without tpm2-tss and sqlite (their
  # own dependency set).
  minimal = base // {
    pname = "cakeys-minimal";
    buildInputs = [ ];
    cargoExtraArgs = "--locked --no-default-features --features camigrate/kwp,cakeys-pkcs11/sign-after-init";
    doCheck = false;
  };

  # cargo-mutants: each mutant is one small change to the code (a function body replaced, an
  # operator flipped), and one the tests still pass with is a place they do not check. Not a
  # check: it takes as long as its scope is wide and always succeeds once the unmutated tests
  # pass. The report is the output, one directory per package: missed.txt (what no test
  # caught), caught.txt, timeout.txt, unviable.txt and outcomes.json.
  #
  # `scopes` is a list of { package, files, workspace ? false }. A package's mutants meet that
  # package's own tests: seconds each, so the unit tier runs in minutes. With `workspace` they
  # meet every crate's tests (a minute each: the whole workspace is rebuilt per mutant). With
  # `tokens`, every crate's tests run under cargo-nextest with a token set per test (as the check
  # phase runs them), so the integration suites can catch mutants too: one mutant at a time, its
  # tests in parallel, stopping at the first that fails; minutes for a mutant no test catches.
  mutants =
    {
      scopes,
      tokens ? false,
      jobs ? 6,
    }:
    let
      run =
        {
          package,
          files,
          workspace ? false,
        }:
        ''
          code=0
          cargo mutants --package ${package} ${
            lib.optionalString (workspace || tokens) "--test-workspace=true"
          } \
            --no-shuffle --colors never --jobs ${toString (if tokens then 1 else jobs)} \
            ${lib.concatMapStringsSep " " (f: "--file ${lib.escapeShellArg f}") files} \
            ${
              # The workspace's features name packages: only a run that tests them all takes them.
              lib.optionalString (workspace || tokens || package == "camigrate") (
                lib.optionalString common.noDefaultFeatures "--no-default-features "
                + "--features ${lib.concatStringsSep "," common.features}"
              )
            } \
            --cargo-arg=--locked --output "$TMPDIR/report-${package}" \
            ${
              # The baseline tests only the mutated package whatever --test-workspace says, and its
              # tests run the tools' binaries: nextest is told to build (and test) the three tools too.
              lib.optionalString tokens
                "--test-tool nextest -- --package cakeys --package caprobe --package camigrate"
            } || code=$?
          # 0: every mutant caught; 2: some missed; 3: some timed out. Those are the report.
          # Anything else (the unmutated tests failing, a bad invocation) fails the build.
          case $code in 0 | 2 | 3) ;; *) exit $code ;; esac
          mkdir -p $out/${package}
          cp -r "$TMPDIR"/report-${package}/mutants.out/* $out/${package}/
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
          ++ [ cargo-mutants ]
          ++ lib.optionals tokens (common.args.nativeCheckInputs ++ [ cargo-nextest ]);
      }
      // lib.optionalAttrs tokens {
        # A token set per test, as the check phase and the coverage report run them.
        ${runner} = "bash ${./test-tokens.sh}";
      }
      // {
        preBuild = lib.optionalString tokens common.args.preCheck;
        postBuild = lib.optionalString tokens common.args.postCheck;
        buildPhaseCargoCommand = lib.concatMapStrings run scopes;
        installPhaseCommand = "";
      }
    );
in
craneLib.buildPackage (
  common.args
  // base
  // {
    inherit cargoArtifacts;
    # cargo-nextest: one process per test, each through nix/test-tokens.sh (cargo's target
    # runner), which gives it a token set of its own: the suites run in parallel, and no test
    # sees what another left on a token. The regular build (nix/package.nix) and the coverage
    # report run them the same way, as does the mutation report with the token suites.
    nativeBuildInputs = base.nativeBuildInputs ++ [ cargo-nextest ];
    ${runner} = "bash ${./test-tokens.sh}";
    cargoTestCommand = "cargo nextest run \${CARGO_PROFILE:+--cargo-profile $CARGO_PROFILE}";
    # No progress bar: the build log is not a terminal, whatever nextest sees.
    cargoTestExtraArgs = "--no-fail-fast --show-progress none";
    passthru = {
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
      minimal = craneLib.buildPackage (minimal // { cargoArtifacts = craneLib.buildDepsOnly minimal; });
      # Mutation testing (docs/DEVELOPMENT.md). `mutants` is the code whose own unit and property
      # tests are its tests, no token needed: `nix build .#mutants`. `mutantsFor` takes one
      # package's files with the token suites running, for the code only they reach:
      #   nix build --impure --expr \
      #     '(builtins.getFlake "git+file://$PWD").packages.x86_64-linux.cakeys-crane.mutantsFor "camigrate" [ "crates/camigrate/src/host.rs" ]'
      mutants = mutants {
        scopes = [
          {
            package = "cakeys-core";
            files = [ "crates/core/src/**/*.rs" ];
          }
          {
            package = "cakeys-profile";
            files = [ "crates/profile/src/**/*.rs" ];
          }
          {
            package = "camigrate";
            files = map (f: "crates/camigrate/src/${f}.rs") [
              "plan"
              "bundle"
              "file"
              "transport"
            ];
          }
        ];
      };
      mutantsFor =
        package: files:
        mutants {
          scopes = [ { inherit package files; } ];
          tokens = true;
        };
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
          cargoLlvmCovExtraArgs = "--no-report --no-fail-fast --show-progress none";
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
              | grep -v '::<_\(, _\)*>$' | sort > $out/uncovered-functions.txt
          ''
          + common.args.postCheck;
        }
      );
    };
  }
)
