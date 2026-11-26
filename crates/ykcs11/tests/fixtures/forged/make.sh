#!/usr/bin/env bash
# The forged PIV attestation chains of ykcs11's attest.rs tests (review 2026-11-24 B-11). A chain
# of Yubico's shape: root -> attestation CA -> PIV CA -> device (f9) -> slot, the device three
# links below the root as firmware 5.7.4+'s are; and beside it what a forger can make, each a
# valid certificate that differs from the genuine chain in the one rule its test names.
#
# - A slot certificate another key signed: by its own key (`slot-self`), by a key under a
#   certificate that takes the device's name (`slot-forged`), or by another device of the same
#   chain, which attests its own key (`slot-b`, under `f9-b`).
# - Longer chains than a PIV attestation's: a device four links below the root (`f9-deep`,
#   under `piv-ca-deep`, with its `slot-deep`), and a slot one link below the device
#   (`slot-sub`, under `device-sub`, a CA the device issued).
#
# Reproducible: each key is derived from its name (SHA-256 of "cakeys forged <name>"), each
# signature is deterministic ECDSA (RFC 6979: OpenSSL 3.2 or later, as the dev shell's), and the
# dates and serials are fixed, so a run writes the same bytes. No secret: the keys are test keys,
# and are not kept. From the repository root, in the dev shell:
# `crates/ykcs11/tests/fixtures/forged/make.sh crates/ykcs11/tests/fixtures/forged`.
set -euo pipefail
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

cat >ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
[slot]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
EOF

dates=(-not_before 20260101000000Z -not_after 20460101000000Z)
serial=0

# The P-256 key of `name`, derived from the name, and its request config with subject CN `cn`.
key() {
  local scalar
  scalar=$(printf 'cakeys forged %s' "$1" | openssl dgst -sha256 -r | cut -d' ' -f1)
  printf 'asn1=SEQUENCE:k\n[k]\nversion=INTEGER:1\nkey=FORMAT:HEX,OCTETSTRING:%s\ncurve=EXPLICIT:0,OID:prime256v1\n' \
    "$scalar" >"$1.asn1"
  openssl asn1parse -genconf "$1.asn1" -noout -out "$1.der"
  openssl ec -inform DER -in "$1.der" -out "$1.key" 2>/dev/null
  sed "s/^CN = placeholder$/CN = $2/" ext.cnf >"$1.cnf"
}

# `name`, subject CN `cn`, self-signed with the extensions of section `ext`.
self_signed() {
  key "$1" "$2"
  serial=$((serial + 1))
  openssl req -new -x509 -key "$1.key" -config "$1.cnf" -extensions "$3" -sha256 -sigopt nonce-type:1 \
    -set_serial "$serial" "${dates[@]}" -out "$1.pem"
}

# `name`, subject CN `cn`, issued by `issuer` (its certificate) with the key of `signer`, with
# the extensions of section `ext`.
issued() {
  key "$1" "$2"
  serial=$((serial + 1))
  openssl req -new -key "$1.key" -config "$1.cnf" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$4.key" -sha256 -sigopt nonce-type:1 \
    -set_serial "$serial" "${dates[@]}" -extfile ext.cnf -extensions "$5" -out "$1.pem" 2>/dev/null
}

slot='YubiKey PIV Attestation 9a'
device='Forged PIV Device Attestation 1'
self_signed root 'Forged Attestation Root 1' ca
issued attestation-ca 'Forged Attestation Intermediate A 1' root root ca
issued piv-ca 'Forged PIV Attestation A 1' attestation-ca attestation-ca ca
issued f9 "$device" piv-ca piv-ca ca
issued slot "$slot" f9 f9 slot
issued f9-b 'Forged PIV Device Attestation 2' piv-ca piv-ca ca
issued slot-b "$slot" f9-b f9-b slot
self_signed slot-self "$slot" slot
# The forger's certificate takes the device's name; only its key is the forger's.
self_signed forger "$device" ca
issued slot-forged "$slot" forger forger slot
issued piv-ca-deep 'Forged PIV Attestation B 1' piv-ca piv-ca ca
issued f9-deep 'Forged PIV Device Attestation 3' piv-ca-deep piv-ca-deep ca
issued slot-deep "$slot" f9-deep f9-deep slot
issued device-sub 'Forged PIV Device Sub-CA 1' f9 f9 ca
issued slot-sub "$slot" device-sub device-sub slot

for f in root attestation-ca piv-ca f9 slot f9-b slot-b slot-self slot-forged piv-ca-deep f9-deep slot-deep \
  device-sub slot-sub; do
  cp "$f.pem" "$out/$f.pem"
done
