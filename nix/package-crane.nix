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

  # The check phase's test command, narrowed by a nextest filter (the coverage pass, postCheck).
  cargoTestCommandFor =
    filter:
    "cargo nextest run \${CARGO_PROFILE:+--cargo-profile $CARGO_PROFILE} ${base.cargoExtraArgs}"
    + " --no-fail-fast --show-progress none -E ${lib.escapeShellArg filter}";

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
  # pass. The report is the output, one directory per package: missed.txt (what no test
  # caught), caught.txt, timeout.txt, unviable.txt and outcomes.json.
  #
  # `scopes` is a list of { package, files, workspace ? false, re ? null }, `re` keeping only the
  # mutants whose name matches (`--re`, e.g. one function). A package's mutants meet that
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
          re ? null,
        }:
        ''
          code=0
          cargo mutants --package ${package} ${
            lib.optionalString (workspace || tokens) "--test-workspace=true"
          } \
            --no-shuffle --colors never --jobs ${toString (if tokens then 1 else jobs)} \
            ${lib.concatMapStringsSep " " (f: "--file ${lib.escapeShellArg f}") files} \
            ${lib.optionalString (re != null) "--re ${lib.escapeShellArg re}"} \
            ${
              # The workspace's features name packages: only a run that tests them all takes them
              # all. camigrate alone takes its own and its dependencies', not the other tools'.
              lib.optionalString (workspace || tokens || package == "camigrate") (
                lib.optionalString common.noDefaultFeatures "--no-default-features "
                + "--features ${
                  lib.concatStringsSep "," (
                    if workspace || tokens then
                      common.features
                    else
                      lib.filter (
                        f:
                        !lib.elem (lib.head (lib.splitString "/" f)) [
                          "cakeys"
                          "caprobe"
                        ]
                      ) common.features
                  )
                }"
              )
            } \
            --cargo-arg=--locked --output "$TMPDIR/report-${package}" \
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
    # Coverage as data (docs/PLAN.md A1, docs/CAPROBE.md "Coverage"): the suites once more, now
    # with every module behind a tracing p11-fault (nix/test-tokens.sh), the built tests reused;
    # then spec-coverage/cakeys.toml is regenerated from that trace and must be what is
    # committed. A second pass, not a traced first one: the first keeps every test talking to
    # its module directly (p11-fault exports the 2.40 interface only).
    postCheck = ''
      # Not run: the coverage test, and the fault suites (nix/test-tokens.sh leaves them
      # untraced, with the other tests it names).
      export CAKEYS_TRACE_DIR=$TMPDIR/coverage-trace
      ${cargoTestCommandFor "not (binary(fault) | test(committed_coverage_is_generated_from_the_trace))"}
      unset CAKEYS_TRACE_DIR
      CAKEYS_COVERAGE_TRACE=$TMPDIR/coverage-trace \
        ${cargoTestCommandFor "test(committed_coverage_is_generated_from_the_trace)"}
    '';
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
      mutantsOf =
        scope:
        mutants {
          scopes = [ scope ];
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
              | { grep -v '::<_\(, _\)*>$' || true; } | sort > $out/uncovered-functions.txt
          '';
        }
      );
    };
  }
)
