# Yubico PIV attestation trust anchors

The pinned roots and the untrusted intermediate pool for the `piv-attestation` commitment
(docs/DESIGN.md §3.7). cakeys verifies a slot attestation certificate ← the device attestation
key's certificate in slot f9 ← these anchors — never to f9 alone, because f9 is user-overwritable
(Yubico: "After the Yubico key is overwritten it can not be brought back").

| File | Role | Source |
|---|---|---|
| `yubico-piv-ca-1.pem` | "Yubico PIV Root CA Serial 263751" (RSA-2048, self-signed) — signs f9 on firmware before 5.7.4 | <https://developers.yubico.com/PKI/yubico-piv-ca-1.pem> |
| `yubico-ca-1.pem` | "Yubico Attestation Root 1" (RSA-2048, self-signed) — terminates the chain on firmware 5.7.4+ | <https://developers.yubico.com/PKI/yubico-ca-1.pem> |
| `yubico-intermediate.pem` | Yubico's published intermediate pool (untrusted store); the 5.7.4+ PIV branch is "Yubico Attestation Intermediate A/B 1" → "Yubico PIV Attestation A/B/B2 1" | <https://developers.yubico.com/PKI/yubico-intermediate.pem> |

The source list is `https://developers.yubico.com/PKI/yubico-ca-certs.txt` (last update
2025-02-03), which Yubico signs with OpenPGP; verify that signature (or fetch and compare
out of band) when updating these files. Yubico's 2025 root CA update is documented at
<https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>.

Not pinned (documented gap): the pre-2018 "piv-attestation-ca-old.pem" root and the Yubico
U2F Attestation CA that signed YubiKey 4 devices manufactured before mid-2017. Cakeys refuses
those devices' attestations as unanchored; pin them the same way if one matters to you.

The unit test `the_yubico_roots_are_pinned` pins every embedded certificate's SPKI digest, so
updating this directory is a deliberate diff.
