# Pure-eval view of keys.toml + keys.lock (docs/CAKEYS.md, "Nix integration").
# Builtins only, so it works without nixpkgs (e.g. inside a test VM).
let
  optionalString = c: s: if c then s else "";
  # One shell word: as is when no shell treats a character of it specially, else single-quoted
  # (nixpkgs' lib.escapeShellArg). keys.toml's names reach `check` unvalidated: this file reads
  # it with fromTOML, never through cakeys' own loader.
  escapeShellArg =
    s:
    if builtins.match "[[:alnum:],._+:@%/-]+" s != null then
      s
    else
      "'${builtins.replaceStrings [ "'" ] [ "'\\''" ] s}'";
in
{
  /**
    mkKeys { config, lock ?, cakeys ?, modules ? { }, featurePrefix ? "token-" } -> { <object> = f }

    One calling convention: every object is a function, and the call resolves the (spec, token)
    pair the arguments name — optional when the object has exactly one.

      keys.signing { }                         # one pair: no arguments needed
      keys.signing { token = "softhsm"; }      # several pairs: name the token
      keys.shared { token = "softhsm"; spec = "shared-sign"; }   # several specs on one token
      keys.signing-cert { scheme = "certhash"; }                # any call can also pin a scheme
      keys.signing { checkArgs = [ "--format" "pkcs11-provider-pem" ]; }   # and pass `check` flags

    The result is plain data, only what evaluation knows without the token:

      type           intrinsic type from keys.toml
      id.<scheme>    portable material CA-IDs the lock pins (id.rfc7093m4; `pubkeyhash` is an
                     input alias)
      spec / token   the resolved pair
      requiredSystemFeatures
                     the token's system feature (keys.toml `tokens.<t>.nix.systemFeature`, default
                     `<featurePrefix><t>`, as the NixOS module advertises it), as the list a
                     derivation's `requiredSystemFeatures` takes
      check          shell command for the pseudo-FOD pre-use check, printing the verified URI:
                     the only URI a consumer should use, never one read from the lock unchecked.
                     The resolved pair is passed explicitly, and `scheme` requires that
                     identity. Interpolates config, lock and module paths, so they become
                     inputs of the consuming derivation (recording a hash rebuilds it). The
                     call's `checkArgs` are appended as given: `cakeys check`'s own flags
                     (`--format pkcs11-provider-pem`, `--uri-module`, `--uri-pin source`, ...),
                     which `cakeys` validates. A `--uri-pin value` PIN is in whatever the output
                     reaches: the build log, a store path.

    A call that does not name exactly one pair throws, listing the choices; so does a lock
    whose `version` this library does not read.

    `modules.<token>` overrides the token's PKCS#11 module path (pass a store path so the
    module is available inside the build sandbox).
  */
  mkKeys =
    {
      config,
      lock ? null,
      cakeys ? null,
      modules ? { },
      featurePrefix ? "token-",
    }:
    let
      cfg = builtins.fromTOML (builtins.readFile config);
      hasLock = lock != null && builtins.pathExists lock;
      lk =
        if hasLock then
          let
            parsed = builtins.fromTOML (builtins.readFile lock);
          in
          if (parsed.version or null) == 1 then
            parsed
          else
            throw "cakeys: ${toString lock}: lock version ${
              builtins.toJSON (parsed.version or null)
            }; this library reads version 1"
        else
          { };
      specs = cfg.specs or { };
      tokens = cfg.tokens or { };

      featuresOf = t: [ (tokens.${t}.nix.systemFeature or "${featurePrefix}${t}") ];

      objectView =
        obj: type:
        let
          specNames = builtins.filter (s: specs.${s}.object == obj) (builtins.attrNames specs);
          allPairs = builtins.concatMap (
            s:
            map (t: {
              spec = s;
              token = t;
            }) (builtins.attrNames specs.${s}.tokens)
          ) specNames;
          show = p: "'${p.spec}' on '${p.token}'";
          fail = msg: throw "cakeys: object '${obj}': ${msg}";
          chosen =
            {
              token ? null,
              spec ? null,
              # The call's other arguments (`scheme`), already checked by its own pattern.
              ...
            }:
            let
              matching = builtins.filter (
                p: (token == null || p.token == token) && (spec == null || p.spec == spec)
              ) allPairs;
            in
            if matching == [ ] then
              fail (
                "no (spec, token) pair"
                + optionalString (token != null) " on token '${token}'"
                + optionalString (spec != null) " for spec '${spec}'"
                + (
                  if allPairs == [ ] then
                    "; the object is realised by no spec"
                  else
                    "; the object has " + builtins.concatStringsSep ", " (map show allPairs)
                )
              )
            else if builtins.length matching > 1 then
              fail (
                "several (spec, token) pairs match; pass token and/or spec: "
                + builtins.concatStringsSep ", " (map show matching)
              )
            else
              builtins.head matching;
        in
        args@{
          token ? null,
          spec ? null,
          # null: whatever the spec computes; else require that identity (e.g. "certhash").
          scheme ? null,
          # `cakeys check`'s own flags, appended as given: what it prints, and how.
          checkArgs ? [ ],
        }:
        let
          pick = chosen args;
          ids = lk.objects.${obj}.ids or { };
        in
        # seq pick: the call itself resolves the (spec, token) pair — missing or ambiguous throws
        # here, whether or not any attribute of the result is demanded. Everything is usable
        # before anything is recorded in the lock (the first-use pseudo-FOD flow): `id` is then
        # empty.
        builtins.seq pick {
          inherit type;
          inherit (pick) spec token;
          # `pubkeyhash` is an input alias of rfc7093m4 (the lock only uses the scheme name).
          id = ids // (if ids ? rfc7093m4 then { pubkeyhash = ids.rfc7093m4; } else { });
          requiredSystemFeatures = featuresOf pick.token;
          check =
            assert cakeys != null || throw "cakeys: mkKeys needs cakeys for check";
            builtins.concatStringsSep " " (
              map escapeShellArg (
                [
                  "${cakeys}/bin/cakeys"
                  "--config"
                  "${config}"
                ]
                ++ (
                  if hasLock then
                    [
                      "--lock"
                      "${lock}"
                    ]
                  else
                    [ ]
                )
                ++ builtins.concatLists (
                  builtins.attrValues (
                    builtins.mapAttrs (t: p: [
                      "--module"
                      "${t}=${p}"
                    ]) modules
                  )
                )
                ++ [
                  "check"
                  "${obj}${optionalString (scheme != null) ".id.${scheme}"}"
                  "--token"
                  pick.token
                  "--spec"
                  pick.spec
                ]
                ++ checkArgs
              )
            );
        };
    in
    builtins.mapAttrs objectView (cfg.objects or { });
}
