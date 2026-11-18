# Google's Cloud KMS PKCS#11 library (docs/CLOUD_HSM.md, "Google Cloud KMS"): the prebuilt
# release, Apache-2.0. Pinned by hash, and its build signature checked against the release key
# the user guide publishes (kmsp11-release-key.pem, copied from it). It links only glibc
# (2.17 or later), with BoringSSL built in; `fips = true` is Google's other build of the same
# release, its BoringSSL in FIPS mode (configure it with `require_fips_mode: true`).
#
# Configuration: a YAML file named by KMS_PKCS11_CONFIG, writable by its owner only; a token is
# a key ring. include/kmsp11.h holds the vendor attributes (CKA_KMS_ALGORITHM and the rest).
{
  lib,
  stdenv,
  fetchurl,
  openssl,
  autoPatchelfHook,
  fips ? false,
}:
let
  # Pinned by its SHA-256 (docs/DEVELOPMENT.md, "Built-in material"): a key file that changed under
  # this expression fails evaluation before it verifies anything.
  releaseKey =
    lib.throwIfNot
      (
        builtins.hashFile "sha256" ./kmsp11-release-key.pem
        == "25d87b5c4ebcc0e9f75d19432172c115056cadb3998f4b9bf224971cf797ddd0"
      )
      "nix/kmsp11-release-key.pem is not the pinned release key: compare it with the user guide's before changing either"
      ./kmsp11-release-key.pem;
in
stdenv.mkDerivation rec {
  pname = if fips then "kmsp11-fips" else "kmsp11";
  version = "1.9";
  src = fetchurl {
    url = "https://github.com/GoogleCloudPlatform/kms-integrations/releases/download/pkcs11-v${version}/libkmsp11-${version}-linux-amd64${lib.optionalString fips "-fips"}.tar.gz";
    hash =
      if fips then
        "sha256-Lpeh7GlsPIzhyLkesyU0BmqYLTtcWPHtSuF0eywRnqg="
      else
        "sha256-U5f5ZQc81dHixD5RSPEC8xp8g1kC+X60HHycDxuHakA=";
  };
  nativeBuildInputs = [
    openssl
    autoPatchelfHook
  ];

  installPhase = ''
    runHook preInstall
    openssl dgst -sha384 -verify ${releaseKey} -signature libkmsp11.so.sig libkmsp11.so
    install -Dm555 libkmsp11.so $out/lib/libkmsp11.so
    install -Dm444 kmsp11.h $out/include/kmsp11.h
    install -Dm444 LICENSE $out/share/doc/kmsp11/LICENSE
    runHook postInstall
  '';

  meta = {
    description = "Google Cloud KMS PKCS#11 library (lib/libkmsp11.so)${lib.optionalString fips ", FIPS build"}";
    homepage = "https://github.com/GoogleCloudPlatform/kms-integrations";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = [ "x86_64-linux" ];
  };
}
