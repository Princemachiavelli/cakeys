# Google's Cloud KMS PKCS#11 library (docs/CLOUD_HSM.md, "Google Cloud KMS"): the prebuilt
# release, Apache-2.0. Pinned by hash, and its build signature checked against the release key
# the user guide publishes (kmsp11-release-key.pem, copied from it). It links only glibc
# (2.17 or later), with BoringSSL built in.
#
# Configuration: a YAML file named by KMS_PKCS11_CONFIG, writable by its owner only; a token is
# a key ring. include/kmsp11.h holds the vendor attributes (CKA_KMS_ALGORITHM and the rest).
{
  lib,
  stdenv,
  fetchurl,
  openssl,
  autoPatchelfHook,
}:
stdenv.mkDerivation rec {
  pname = "kmsp11";
  version = "1.9";
  src = fetchurl {
    url = "https://github.com/GoogleCloudPlatform/kms-integrations/releases/download/pkcs11-v${version}/libkmsp11-${version}-linux-amd64.tar.gz";
    hash = "sha256-U5f5ZQc81dHixD5RSPEC8xp8g1kC+X60HHycDxuHakA=";
  };
  nativeBuildInputs = [
    openssl
    autoPatchelfHook
  ];

  installPhase = ''
    runHook preInstall
    openssl dgst -sha384 -verify ${./kmsp11-release-key.pem} -signature libkmsp11.so.sig libkmsp11.so
    install -Dm555 libkmsp11.so $out/lib/libkmsp11.so
    install -Dm444 kmsp11.h $out/include/kmsp11.h
    install -Dm444 LICENSE $out/share/doc/kmsp11/LICENSE
    runHook postInstall
  '';

  meta = {
    description = "Google Cloud KMS PKCS#11 library (lib/libkmsp11.so)";
    homepage = "https://github.com/GoogleCloudPlatform/kms-integrations";
    license = lib.licenses.asl20;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = [ "x86_64-linux" ];
  };
}
