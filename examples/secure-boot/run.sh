#!/usr/bin/env bash
# examples/secure-boot's db key on a software TPM: generated there, its certificate issued from
# a CSR the TPM signs, then an EFI binary signed with it through the check sign.nix's build
# runs, and the signature verified. The YubiKey's PK and KEK are validated only (no device
# here): a software KEK stands in to issue db's certificate. Each step states the exit code it
# expects (examples/lib.sh): checks.examples runs it.
#
# Needs TPM2_PKCS11_MODULE, PKCS11_PROVIDER_DIR (pkcs11-provider's ossl-modules), SYSTEMD_SBSIGN
# (systemd's lib/systemd/systemd-sbsign), EFI_STUB (an EFI binary to sign, e.g. systemd's
# linuxx64.efi.stub), and on PATH cakeys, openssl, sbverify and the TPM stack.
# shellcheck source=examples/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

tpm_token secure-boot
export SB_TPM_PIN_FILE=$work/pin
install -m 644 "$examples/secure-boot/keys.toml" keys.toml
export CAKEYS_CONFIG=$work/keys.toml
module=(--module "tpm=$TPM2_PKCS11_MODULE")

# Every pair against its token's profiles, the YubiKey's included: RSA 2048 generated in a PIV
# slot, with an attestation.
expect 0 cakeys validate
# db, born in the TPM and recorded.
expect 0 cakeys "${module[@]}" create db --token tpm

# Its certificate: a CSR the TPM signs, issued by KEK (here a software stand-in).
openssl_pkcs11 "$TPM2_PKCS11_MODULE"
openssl req -x509 -newkey rsa:2048 -nodes -keyout kek.key -subj "/CN=KEK (stand-in)" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -days 1 -out KEK.crt 2>/dev/null
expect 0 cakeys "${module[@]}" check db --format pkcs11-provider-pem --uri-pin source
cp stdout db.pem
expect 0 openssl req -new -key db.pem -subj "/CN=Secure Boot db" -out db.csr
expect 0 openssl x509 -req -in db.csr -CA KEK.crt -CAkey kek.key -days 1 -out db.crt

# What sign.nix's build does, in its environment: check db, then sign with the URI the check
# printed. systemd-sbsign loads pkcs11-provider itself (from OPENSSL_MODULES; no OpenSSL
# configuration), which reaches the TPM through PKCS11_PROVIDER_MODULE and reads the PIN by
# reference (pin-source).
expect 0 cakeys "${module[@]}" check db --uri-pin source
uri=$(<stdout)
expect 0 env -u OPENSSL_CONF OPENSSL_MODULES="$PKCS11_PROVIDER_DIR" PKCS11_PROVIDER_MODULE="$TPM2_PKCS11_MODULE" \
  "$SYSTEMD_SBSIGN" sign --private-key-source=provider:pkcs11 --private-key="$uri" \
  --certificate=db.crt --output=signed.efi "$EFI_STUB"
# The firmware's view: the signature chains to KEK, as db's enrolled certificate does.
expect 0 sbverify --cert KEK.crt signed.efi
