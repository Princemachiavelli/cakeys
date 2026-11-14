# Line counts and how they move between runs and git revisions (.mezura/config.txt). Not in
# nixpkgs, so built from its crates.io release.
{
  lib,
  rustPlatform,
  fetchCrate,
}:

rustPlatform.buildRustPackage rec {
  pname = "mezura";
  version = "3.5.0";

  src = fetchCrate {
    inherit pname version;
    hash = "sha256-6JJMJhU9KJvr24YlARTrG7O32yuefK15MTpci3PANFY=";
  };

  cargoHash = "sha256-jJMoYt+7eIrURRh6Lf6k+cj16+FIb8+ZGUCVCbhN3cw=";

  # The tests read ../mezura-core/data from the upstream workspace, which the published crate
  # leaves out, and drive git and a remote repository.
  doCheck = false;

  meta = {
    description = "Count the lines of a codebase and track how the figures move between runs and git revisions";
    homepage = "https://github.com/subamanis/mezura";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "mezura";
  };
}
