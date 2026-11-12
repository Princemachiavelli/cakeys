# Pure-eval view of keys.toml + keys.lock (PLAN.md, "Nix integration").
# Builtins only, so it works without nixpkgs (e.g. inside a test VM).
let
  genAttrs =
    names: f:
    builtins.listToAttrs (
      map (n: {
        name = n;
        value = f n;
      }) names
    );
  unique = builtins.foldl' (acc: x: if builtins.elem x acc then acc else acc ++ [ x ]) [ ];
  optionalString = c: s: if c then s else "";
in
{
  /**
    mkKeys { config, lock ?, cakeys ?, modules ? { } } -> { <object> = { ... }; }

    Per object:
      type                    intrinsic type from keys.toml
      id.<scheme>             portable material CA-IDs from the lock (e.g. id.rfc7093m4)
      specs.<spec>.{uri,mode,specDigest,module,tokenInfo,functions,rsf}.<token>
      uri / mode / specDigest / module / tokenInfo / functions / rsf .<token>
                              shortcuts when the object has exactly one spec on that token
      check { token ?, spec ?, scheme ? }
                              shell command for the pseudo-FOD pre-use check; prints the URI.
                              Interpolates config, lock and module paths, so they become inputs
                              of the consuming derivation (recording a hash rebuilds it).

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

      rsfOf = t: [ (tokens.${t}.systemFeature or "token-${t}") ];

      specView =
        s:
        let
          tks = builtins.attrNames specs.${s}.tokens;
          real =
            t:
            realisations.${s}.${t}
              or (throw "cakeys: spec '${s}' has no realisation on token '${t}' in the lock; run `cakeys realise ${s} --token ${t} --update-lock`");
        in
        {
          tokens = tks;
          uri = genAttrs tks (t: (real t).uri);
          mode = genAttrs tks (t: (real t).mode);
          specDigest = genAttrs tks (t: (real t).specDigest);
          # Provenance: { path, description, manufacturer, version, cryptoki } / { model, serial, firmware }.
          module = genAttrs tks (t: (real t).module or null);
          tokenInfo = genAttrs tks (t: (real t).token or null);
          functions = genAttrs tks (
            t:
            builtins.listToAttrs (
              map (m: {
                name = m;
                value = true;
              }) ((real t).mechanisms or [ ])
            )
          );
          rsf = genAttrs tks rsfOf;
        };

      objectView =
        obj: type:
        let
          specNames = builtins.filter (s: specs.${s}.object == obj) (builtins.attrNames specs);
          views = genAttrs specNames specView;
          pairs = builtins.concatMap (
            s:
            map (t: {
              spec = s;
              token = t;
            }) views.${s}.tokens
          ) specNames;
          tokenNames = unique (map (p: p.token) pairs);
          onToken =
            t:
            let
              m = builtins.filter (p: p.token == t) pairs;
            in
            if builtins.length m == 1 then
              views.${(builtins.head m).spec}
            else
              throw "cakeys: object '${obj}' has several specs on token '${t}'; use specs.<spec>";
          perToken = field: genAttrs tokenNames (t: (onToken t).${field}.${t});
        in
        {
          inherit type;
          # `pubkeyhash` is an input alias of rfc7093m4 (the lock only uses the scheme name).
          id =
            let
              ids = lk.objects.${obj}.ids or { };
            in
            ids // (if ids ? rfc7093m4 then { pubkeyhash = ids.rfc7093m4; } else { });
          specs = views;
          uri = perToken "uri";
          mode = perToken "mode";
          specDigest = perToken "specDigest";
          module = perToken "module";
          tokenInfo = perToken "tokenInfo";
          functions = perToken "functions";
          rsf = genAttrs tokenNames rsfOf;
          check =
            {
              token ? null,
              spec ? null,
              # null: whatever the spec computes; else require that scheme (e.g. "certhash").
              scheme ? null,
            }:
            assert cakeys != null || throw "cakeys: mkKeys needs cakeys for check";
            builtins.concatStringsSep " " (
              [
                "${cakeys}/bin/cakeys"
                "--config ${config}"
              ]
              ++ (if hasLock then [ "--lock ${lock}" ] else [ ])
              ++ builtins.attrValues (builtins.mapAttrs (t: p: "--module ${t}=${p}") modules)
              ++ [ "check ${obj}${optionalString (scheme != null) ".id.${scheme}"}" ]
              ++ [
                (optionalString (token != null) "--token ${token}")
                (optionalString (spec != null) "--spec ${spec}")
              ]
            );
        };
    in
    builtins.mapAttrs objectView (cfg.objects or { });
}
