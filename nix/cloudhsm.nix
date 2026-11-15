# The AWS CloudHSM Client SDK 5 (docs/CLOUD_HSM.md, "AWS CloudHSM"): the PKCS#11 library, the
# OpenSSL dynamic engine and the OpenSSL 3 provider, from AWS's own packages. Of the distros AWS
# builds for, Ubuntu 26.04 is the closest to NixOS: the newest glibc (the binaries need 2.39)
# and the only one with all three packages. Each binary links only libc, libm, libgcc_s and the
# loader; OpenSSL is linked in statically, so the engine and the provider load into any
# OpenSSL 3.
#
# Unfree: the packages are under the AWS Customer Agreement. The repository carries the URLs and
# the hashes (AWS's published SHA-256, latest-releases.html), never the files.
#
# Configuration: every library reads the file named by CLOUDHSM_CONFIG_FILENAME, falling back to
# /opt/cloudhsm/etc/<package>.cfg. The configure-* tools write under /opt/cloudhsm/etc only.
# etc/ here holds AWS's templates, with %%HSM_IP_ADDRESS%% still in them.
{
  lib,
  stdenv,
  fetchurl,
  dpkg,
  autoPatchelfHook,
}:
let
  version = "5.18.1";

  mk =
    {
      pname,
      hash,
      description,
      # A path under $out/lib and the library it links to, where OpenSSL looks for it.
      openssl ? null,
    }:
    stdenv.mkDerivation {
      inherit pname version;
      src = fetchurl {
        url = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Resolute/${pname}_${version}-1_u26.04_amd64.deb";
        inherit hash;
      };
      nativeBuildInputs = [
        dpkg
        autoPatchelfHook
      ];
      buildInputs = [ (lib.getLib stdenv.cc.cc) ];

      unpackPhase = ''
        runHook preUnpack
        dpkg-deb -x $src .
        runHook postUnpack
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p $out/share/doc/${pname}
        cp -r opt/cloudhsm/{bin,lib,etc} $out/
        if [ -d opt/cloudhsm/include ]; then cp -r opt/cloudhsm/include $out/; fi
        cp opt/cloudhsm/doc/*/LICENSE.txt $out/share/doc/${pname}/
        ${lib.optionalString (openssl != null) ''
          mkdir -p $out/lib/${dirOf openssl.path}
          ln -s ../${openssl.target} $out/lib/${openssl.path}
        ''}
        runHook postInstall
      '';

      meta = {
        inherit description;
        homepage = "https://docs.aws.amazon.com/cloudhsm/latest/userguide/client-history.html";
        license = lib.licenses.unfree;
        sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
        platforms = [ "x86_64-linux" ];
      };
    };
in
{
  cloudhsm-pkcs11 = mk {
    pname = "cloudhsm-pkcs11";
    hash = "sha256-G8RcodYvITOI98TobpBEgD6bBj1Mjq8gBXVXTeN0WzM=";
    description = "AWS CloudHSM PKCS#11 library (lib/libcloudhsm_pkcs11.so)";
  };
  cloudhsm-dyn = mk {
    pname = "cloudhsm-dyn";
    hash = "sha256-/huzl2YVSZm4sAgF5U88yjlXpxBBdZiDwf0hYGlFsvA=";
    description = "AWS CloudHSM OpenSSL dynamic engine (OPENSSL_ENGINES=lib/engines-3, engine cloudhsm)";
    openssl = {
      path = "engines-3/cloudhsm.so";
      target = "libcloudhsm_openssl_engine.so";
    };
  };
  cloudhsm-openssl-provider = mk {
    pname = "cloudhsm-openssl-provider";
    hash = "sha256-BqfW34ApZJQDfsE0GC3LQ2PT/PPCel4CapVApiO2xdg=";
    description = "AWS CloudHSM OpenSSL 3 provider (OPENSSL_MODULES=lib/ossl-modules, provider cloudhsm)";
    openssl = {
      path = "ossl-modules/cloudhsm.so";
      target = "libcloudhsm_openssl_provider.so";
    };
  };
}
