# Pure-eval view of keys.toml + keys.lock (docs/DESIGN.md §7.1).
# Builtins only, so it works without nixpkgs (e.g. inside a test VM).
let
  optionalString = c: s: if c then s else "";
in
{
  /**
    mkKeys { config, lock ?, cakeys ?, modules ? { } } -> { <object> = f }

    One calling convention: every object is a function, and the call resolves the (spec, token)
    pair the arguments name — optional when the object has exactly one.

      keys.signing { }                         # one pair: no arguments needed
      keys.signing { token = "softhsm"; }      # several pairs: name the token
      keys.shared { token = "softhsm"; spec = "shared-sign"; }   # several specs on one token
      keys.signing-cert { scheme = "certhash"; }                # any call can also pin a scheme

    The result is plain data:

      type           intrinsic type from keys.toml
      id.<scheme>    portable material CA-IDs from the lock (id.rfc7093m4; `pubkeyhash` is an
                     input alias)
      spec / token   the resolved pair
      uri / mode / specDigest / module / tokenInfo / functions
                     from the pair's realisation (observed and provenance)
      requiredSystemFeatures
                     the token's system feature (keys.toml `tokens.<t>.systemFeature`, default
                     `token-<t>`), as the list a derivation's `requiredSystemFeatures` takes
      check          shell command for the pseudo-FOD pre-use check, printing the URI; the
                     resolved pair is passed explicitly, and `scheme` requires that identity.
                     Interpolates config, lock and module paths, so they become inputs of the
                     consuming derivation (recording a hash rebuilds it).

    A call that does not name exactly one pair throws, listing the choices.

    `modules.<token>` overrides the token's PKCS#11 module path (pass a store path so the
    module is available inside the build sandbox).
  */
  mkKeys =
    {
      config,
      lock ? null,
      cakeys ? null,
      modules ? { },
    }:
    let
      cfg = builtins.fromTOML (builtins.readFile config);
      hasLock = lock != null && builtins.pathExists lock;
      lk = if hasLock then builtins.fromTOML (builtins.readFile lock) else { };
      specs = cfg.specs or { };
      tokens = cfg.tokens or { };
      realisations = lk.realisations or { };

      featuresOf = t: [ (tokens.${t}.systemFeature or "token-${t}") ];

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
        }:
        let
          pick = chosen args;
          real =
            realisations.${pick.spec}.${pick.token}
              or (fail "spec '${pick.spec}' has no realisation on token '${pick.token}' in the lock; run `cakeys realise ${pick.spec} --token ${pick.token}`");
          ids = lk.objects.${obj}.ids or { };
        in
        # seq pick: the call itself resolves the (spec, token) pair — missing or ambiguous throws
        # here, whether or not any attribute of the result is demanded. The realisation stays
        # lazy: `check`, `id`, `type` and `requiredSystemFeatures` are usable before anything is
        # recorded in the lock (the first-use pseudo-FOD flow), and only the realisation's own
        # fields throw.
        builtins.seq pick {
          inherit type;
          inherit (pick) spec token;
          # `pubkeyhash` is an input alias of rfc7093m4 (the lock only uses the scheme name).
          id = ids // (if ids ? rfc7093m4 then { pubkeyhash = ids.rfc7093m4; } else { });
          uri = real.observed.uri or null;
          inherit (real) mode specDigest;
          # Provenance: { path, description, manufacturer, version, cryptoki } / { model, serial, firmware }.
          module = real.provenance.module or null;
          tokenInfo = real.provenance.token or null;
          functions = builtins.listToAttrs (
            map (m: {
              name = m;
              value = true;
            }) (real.observed.mechanisms or [ ])
          );
          requiredSystemFeatures = featuresOf pick.token;
          check =
            assert cakeys != null || throw "cakeys: mkKeys needs cakeys for check";
            builtins.concatStringsSep " " (
              [
                "${cakeys}/bin/cakeys"
                "--config ${config}"
              ]
              ++ (if hasLock then [ "--lock ${lock}" ] else [ ])
              ++ builtins.attrValues (builtins.mapAttrs (t: p: "--module ${t}=${p}") modules)
              ++ [
                "check ${obj}${optionalString (scheme != null) ".id.${scheme}"}"
                "--token ${pick.token}"
                "--spec ${pick.spec}"
              ]
            );
        };
    in
    builtins.mapAttrs objectView (cfg.objects or { });
}
