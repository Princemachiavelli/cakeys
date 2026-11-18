# pkcs11-check (docs/PLAN.md A6): a vendor-neutral PKCS#11 conformance and behaviour suite over
# a ctypes binding, run against the reference modules as a second opinion beside caprobe's
# profiles, never as a check. Not in nixpkgs, so built from its tagged release; so is its one
# dependency nixpkgs lacks, pytest-reportlog.
{
  lib,
  python3Packages,
  fetchFromGitHub,
  fetchPypi,
}:
let
  pytest-reportlog = python3Packages.buildPythonPackage rec {
    pname = "pytest-reportlog";
    version = "1.0.0";
    pyproject = true;
    src = fetchPypi {
      pname = "pytest_reportlog";
      inherit version;
      hash = "sha256-da7DqSu1NFbD4ChgWmNledJvMcbx4DWtn3BsIDz8t04=";
    };
    build-system = with python3Packages; [
      hatchling
      hatch-vcs
    ];
    dependencies = [ python3Packages.pytest ];
    pythonImportsCheck = [ "pytest_reportlog" ];
    meta.license = lib.licenses.mit;
  };
in
python3Packages.buildPythonApplication rec {
  pname = "pkcs11-check";
  version = "0.2.3";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "mingulov";
    repo = "pkcs11-check";
    tag = "v${version}";
    hash = "sha256-h5sVOpDVjJ9VO3JB5GWQ3fW6L4f9EvsFvSYqfsExyB8=";
  };

  build-system = [ python3Packages.hatchling ];
  dependencies =
    (with python3Packages; [
      typer
      rich
      pydantic
      pydantic-settings
      psutil
      pytest
      pytest-benchmark
      pytest-xdist
      pytest-timeout
      asn1crypto
      cryptography
      hypothesis
    ])
    ++ [ pytest-reportlog ];

  # It runs the suite in subprocesses of the bare interpreter (`sys.executable -m ...`), which
  # see none of the site directories the wrapper adds inside the script: hand them the same.
  makeWrapperArgs = [
    "--prefix"
    "PYTHONPATH"
    ":"
    "${placeholder "out"}/${python3Packages.python.sitePackages}:${python3Packages.makePythonPath dependencies}"
  ];

  # Its own tests drive the suite against modules it builds or downloads; what matters here is
  # that both entry points load.
  doCheck = false;
  pythonImportsCheck = [ "pkcs11_check" ];

  meta = {
    description = "Broad, vendor-neutral PKCS#11 behaviour and conformance test client";
    homepage = "https://github.com/mingulov/pkcs11-check";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "pkcs11-check";
  };
}
