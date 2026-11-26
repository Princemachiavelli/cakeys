//! `YubiKey` PIV attestation (`piv-attestation`, docs/DESIGN.md §3.7), which the host verifies.
//!
//! For each key slot, ykcs11 exposes the on-demand attestation certificate that the device signed
//! with its attestation key in slot f9 (for example, `"X.509 Certificate for PIV Attestation
//! 9a"`, which shares the slot's `CKA_ID`). Yubico signs each device's f9 certificate with a PIV
//! CA. cakeys verifies the whole chain against a *pinned* root, and never against f9 alone,
//! because anyone who holds the management key can overwrite f9.
//!
//! The commitment hashes the fields that the certificate asserts, not its bytes. The device
//! generates the certificate on demand with a random serial number and a randomized ECDSA
//! signature, so only the asserted content is stable.
//!
//! The chain walk itself (signatures, `basicConstraints`, validity) is generic, and it is in
//! `cakeys_core::chain`. The parts that are specific to PIV are here: the intermediate pool, the
//! roots, and the check of what the chain asserts.

use cakeys_core::chain::{Cert, Start, chain_to_anchor, link};
use cakeys_core::id;
use cakeys_core::{Check, KmError, Reason, Result};
use x509_cert::der::asn1::ObjectIdentifier;

/// The label prefix that ykcs11 gives to every slot's attestation certificate. The suffix is the
/// slot, for example "9a". The slot f9 device certificate itself has the bare label without a
/// suffix.
pub(crate) const ATTESTATION_LABEL: &str = "X.509 Certificate for PIV Attestation";

/// Yubico's PIV attestation extension OIDs (the Yubico Attestation OID arc 1.3.6.1.4.1.41482.3).
const FIRMWARE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
const SERIAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
const PIN_TOUCH_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
const FORMFACTOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.9");

/// The computed `piv-attestation` commitment: the canonical ID, and the anchor against which the
/// chain was verified.
#[derive(Debug)]
pub(crate) struct PivAttested {
    pub id: String,
    pub root: String,
}

/// Verifies the slot's attestation certificate, and the device certificate that signed it,
/// against the pinned anchors (with Yubico's intermediate pool), and then computes the commitment
/// over what they assert.
///
/// `spki` is the canonical SPKI of the object's material, which is the same bytes that its
/// `rfc7093m4` ID hashes. The attestation must name exactly that key. This requirement makes an
/// attested identity *verifiable as key identity* on a token where no attestation exists. A copy
/// of the key on another token cannot be attested (Yubico attests only keys that were generated
/// on the device), but the shared `rfc7093m4` ID, which is checked against the attestation's
/// subject, still links the material.
///
/// `at` is a time in seconds since the Unix epoch, or `None` when the dates are not checked.
/// Every certificate, from the slot certificate to the pinned root, must be valid at that time
/// (ISSUES.md B8). Only `check` makes this failure fatal; the other verbs turn it into a warning
/// (`ChainTime::Warn`).
pub(crate) fn verify_piv_attestation(
    slot: &[u8],
    device: &[u8],
    anchors: &[Cert],
    pool: &[Cert],
    spki: &[u8],
    at: Option<u64>,
) -> Result<PivAttested> {
    let slot = Cert::from_der(slot.to_vec())?;
    let device = Cert::from_der(device.to_vec())?;
    // The device certificate must chain to a pinned root, and that same device attestation key
    // must have signed the slot certificate. Real chains have one link (f9 ← classic root) or
    // three links (f9 ← PIV intermediate ← attestation intermediate ← root, on firmware 5.7.4
    // and later). A longer chain is not a PIV attestation chain.
    // The slot link follows every rule that the walk applies to its links (review 2026-11-24
    // A-7): the device certificate may issue certificates (CA, keyCertSign), neither certificate
    // has a critical extension that cakeys does not process, both are valid at `at`, and the
    // device's key signed the slot's certificate.
    let anchor = chain_to_anchor(&device, Start::Intermediate, anchors, pool, at, 3)?;
    link(&slot, Start::EndEntity, &device, at).map_err(|e| {
        KmError::Conflict(Reason::check(
            Check::AttestPivSlotByDevice,
            format!("the slot attestation certificate does not link to the device attestation certificate: {e}"),
        ))
    })?;
    // The attested key is the certificate's subject key. It must be the material that the
    // identity is for. Otherwise the attestation attests a different key, which is a conflict
    // (exit 13) and never a pass.
    let subject = slot.spki()?;
    if spki != subject {
        return Err(KmError::Conflict(Reason::check(
            Check::AttestPivSlotKey,
            format!(
                "the attestation names the public key {}, but the object's material is {}",
                id::sri(&subject),
                id::sri(spki)
            ),
        )));
    }
    Ok(PivAttested {
        id: id::piv_attestation_id(
            &device.spki()?,
            &subject,
            &slot.extension(&FIRMWARE),
            &slot.extension(&SERIAL),
            &slot.extension(&PIN_TOUCH_POLICY),
            &slot.extension(&FORMFACTOR),
        ),
        root: id::sri(&anchor.spki()?),
    })
}

/// Reads the fuzz target's input (`crate::fuzzing::piv_attestation`): a big-endian two-byte
/// length, the slot certificate's DER, and then the device certificate's DER. It verifies them
/// at a fixed time (2030) against the slot certificate's own key, first against Yubico's pinned
/// roots with their pool and then against the test fixture's root, which a fuzzed chain can
/// reach. This function is never built into a product, because the fixture root is a test key.
#[cfg(any(test, feature = "fuzzing", kani))]
pub(crate) fn fuzz_piv_attestation(bytes: &[u8], anchors: &[Cert], pool: &[Cert]) -> Result<()> {
    static FIXTURE_ROOT: std::sync::LazyLock<Vec<Cert>> = std::sync::LazyLock::new(|| {
        cakeys_core::chain::pem_certs(include_str!("../tests/fixtures/root.pem")).expect("the fixture root parses")
    });
    let short = || KmError::Validation("shorter than its length prefix".into());
    let [hi, lo, rest @ ..] = bytes else { return Err(short()) };
    let (slot, device) = rest.split_at_checked(usize::from(u16::from_be_bytes([*hi, *lo]))).ok_or_else(short)?;
    let spki = Cert::from_der(slot.to_vec()).and_then(|c| c.spki()).unwrap_or_default();
    let at = Some(1_893_456_000);
    verify_piv_attestation(slot, device, anchors, pool, &spki, at)
        .or_else(|_| verify_piv_attestation(slot, device, &FIXTURE_ROOT, &[], &spki, at))
        .map(drop)
}

/// Returns the pooled Yubico intermediates that a PIV chain may pass through: the PIV attestation
/// CAs and the generic "Attestation Intermediate" CAs above them. Yubico's published pool also
/// holds the FIDO, `OpenPGP`, SD and `YubiHSM` attestation CAs under the same "Yubico Attestation
/// Root 1". A device certificate that one of those CAs issued is not PIV evidence, so the
/// function leaves those CAs out.
pub(crate) fn piv_pool(pool: Vec<Cert>) -> Vec<Cert> {
    pool.into_iter()
        .filter(|c| {
            let subject = c.parsed().tbs_certificate().subject().to_string();
            ["CN=Yubico PIV Attestation", "CN=Yubico Attestation Intermediate"].iter().any(|p| subject.starts_with(p))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::chain::pem_certs;
    use cakeys_core::testing::assert_fires;
    use x509_cert::der::DateTime;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    /// Returns the canonical SPKI of a fixture public key, read from its PEM.
    fn spki_of(name: &str) -> Vec<u8> {
        id::spki_canonical(&der_of(name)).unwrap()
    }

    /// Returns the DER of a PEM fixture (a certificate or a public key).
    fn der_of(name: &str) -> Vec<u8> {
        x509_cert::der::pem::decode_vec(&fixture(name)).unwrap().1
    }

    /// The embedded Yubico anchors and the intermediate pool parse, and every published
    /// intermediate chains to an anchor. This test runs the real chain walk on Yubico's own
    /// certificates.
    #[test]
    fn the_yubico_roots_are_pinned() {
        let mut anchors = pem_certs(include_str!("../roots/yubico-piv-ca-1.pem")).unwrap();
        anchors.extend(pem_certs(include_str!("../roots/yubico-ca-1.pem")).unwrap());
        assert_eq!(anchors.len(), 2);
        let pool = pem_certs(include_str!("../roots/yubico-intermediate.pem")).unwrap();
        assert_eq!(pool.len(), 15, "Yubico published 15 intermediates (2025-02-03)");
        // The anchors are pinned by digest, so an update of the roots directory is a deliberate
        // change. The classic PIV root (RSA-2048, "Yubico PIV Root CA Serial 263751") signs the
        // f9 certificates of firmware before 5.7.4, and "Yubico Attestation Root 1" ends the
        // chains of firmware 5.7.4 and later.
        assert_eq!(
            anchors[0].spki().map(|s| id::sri(&s)).unwrap(),
            "sha256-Sxhbd4PXkvkCzZYM0clBeXfYjTB3sWvJ69zvcxPy4p4="
        );
        assert_eq!(
            anchors[1].spki().map(|s| id::sri(&s)).unwrap(),
            "sha256-H0PiuI6WSl0DuAWLuqztaBmcklYgDxuyjqqy+CoeBvI="
        );
        // The whole published pool chains to the pinned roots.
        for c in &pool {
            chain_to_anchor(c, Start::Intermediate, &anchors, &pool, None, 3).unwrap();
        }
        // A PIV chain passes only through the PIV CAs and the generic intermediates above them.
        // The CAs of the other products (FIDO, OpenPGP, SD, YubiHSM) issue no PIV device
        // certificates.
        let piv: Vec<String> = piv_pool(pem_certs(include_str!("../roots/yubico-intermediate.pem")).unwrap())
            .iter()
            .map(|c| c.parsed().tbs_certificate().subject().to_string())
            .collect();
        assert_eq!(
            piv,
            [
                "CN=Yubico Attestation Intermediate A 1",
                "CN=Yubico Attestation Intermediate B 1",
                "CN=Yubico PIV Attestation A 1",
                "CN=Yubico PIV Attestation B 1",
                "CN=Yubico PIV Attestation B2 1",
            ]
        );
    }

    /// The fixture chain (root → device f9 → slot attestation) verifies against its anchor, and
    /// the commitment is the pinned digest of what the chain asserts. Material that the
    /// attestation does not name is a conflict. This cross-check makes sure that an attestation
    /// identifies the key of the object.
    #[test]
    fn fixture_chain_verifies_and_pins() {
        let anchors = pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap();
        let attested = verify_piv_attestation(
            &der_of("slot.pem"),
            &der_of("f9.pem"),
            &anchors,
            &[],
            &spki_of("slotpub.pem"),
            None,
        )
        .unwrap();
        assert_eq!(attested.id, "sha256-gKyFL3YX9/6UtxWv5JbcU4a5Rj5Ev9IVC0SV25gIQoc=");
        assert_eq!(attested.root, id::sri(&anchors[0].spki().unwrap()));
        // Other material: the attestation names the slot's key, not another key's.
        let err = verify_piv_attestation(
            &der_of("slot.pem"),
            &der_of("f9.pem"),
            &anchors,
            &[],
            &spki_of("slot2pub.pem"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("the attestation names"), "{err}");
        // No pinned anchor, as when f9 was overwritten with a self-made key or when the device is
        // from another vendor.
        let err =
            verify_piv_attestation(&der_of("slot.pem"), &der_of("f9.pem"), &[], &[], &spki_of("slotpub.pem"), None)
                .unwrap_err();
        assert!(err.to_string().contains("signed by no pinned root"), "{err}");
    }

    /// The slot link follows the chain's rules (review 2026-11-24 A-7). A device certificate whose
    /// keyUsage lacks keyCertSign cannot sign a slot certificate, and a slot certificate with a
    /// critical extension that cakeys does not process is refused, as each one is anywhere in the
    /// walk. The test uses core's chain-rules fixtures, in which each `piv-` chain differs from
    /// the `piv-slot` chain in one rule (openssl refuses both).
    #[test]
    fn the_slot_link_keeps_the_chain_rules() {
        let rule = |name: &str| {
            let pem = std::fs::read_to_string(format!(
                "{}/../core/tests/fixtures/chain-rules/{name}.pem",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            pem_certs(&pem).unwrap().remove(0)
        };
        let anchors = [rule("piv-root")];
        let verify = |slot: &str, device: &str| {
            let slot = rule(slot);
            verify_piv_attestation(slot.der(), rule(device).der(), &anchors, &[], &slot.spki().unwrap(), None)
        };
        verify("piv-slot", "piv-device").unwrap();
        let e = verify("piv-slot-no-certsign", "piv-device-no-certsign").unwrap_err();
        assert!(e.to_string().contains("its keyUsage lacks keyCertSign"), "{e}");
        let e = verify("piv-slot-critical", "piv-device").unwrap_err();
        assert!(e.to_string().contains("the critical extension 1.2.3.4"), "{e}");
        // A slot certificate that another key signed (the case of review 2026-11-24 B-11).
        let e = verify("piv-slot-no-certsign", "piv-device").unwrap_err();
        assert!(e.to_string().contains("signature does not verify"), "{e}");
    }

    /// Returns a certificate of the forged chains (tests/fixtures/forged/make.sh). The fixtures
    /// hold one chain in Yubico's shape (root, attestation CA, PIV CA, device (f9) and slot) and
    /// the forgeries next to it.
    fn forged(name: &str) -> Cert {
        pem_certs(&String::from_utf8(fixture(&format!("forged/{name}.pem"))).unwrap()).unwrap().remove(0)
    }

    /// Verifies the slot certificate `slot` as the attestation by the device `device` of the
    /// slot's own key. The chain goes to the forged root through the forged attestation and PIV
    /// CAs and the certificates that `more` names.
    fn verify_forged(slot: &str, device: &str, more: &[&str]) -> Result<PivAttested> {
        let slot = forged(slot);
        let pool: Vec<Cert> = ["attestation-ca", "piv-ca"].iter().chain(more).map(|n| forged(n)).collect();
        verify_piv_attestation(slot.der(), forged(device).der(), &[forged("root")], &pool, &slot.spki().unwrap(), None)
    }

    /// A slot attestation comes from the device only when the device's key signed it (review
    /// 2026-11-24 B-11). f9 certificates are public, so the fact that an f9 certificate chains to
    /// a pinned root says nothing about a slot certificate that another key signed. Next to a
    /// genuine device three links below the root, each forgery is a valid certificate of the key
    /// that it names: `slot-self` is signed by its own key, `slot-forged` has an issuer that takes
    /// the device's name, and `slot-b` is another device's genuine attestation of its own key. The
    /// link to the device refuses each forgery, while the genuine pairs verify.
    #[test]
    fn a_slot_certificate_signed_by_another_key_is_refused() {
        verify_forged("slot", "f9", &[]).unwrap();
        verify_forged("slot-b", "f9-b", &[]).unwrap();
        for slot in ["slot-self", "slot-forged", "slot-b"] {
            assert_fires(&verify_forged(slot, "f9", &[]), Check::AttestPivSlotByDevice);
        }
    }

    /// A PIV attestation chain consists of the slot, the device, and at most three links from the
    /// device to the root (UD-19). A device four links below the root is refused, although the
    /// walk alone accepts that chain with a limit of four. A slot one link further below the
    /// device, under a CA that the device issued (`device-sub`), is refused whichever of the two
    /// certificates is presented as the device. With f9 as the device, the slot's link to f9 is
    /// refused. With the CA as the device, the chain length is refused. Each link of that chain is
    /// otherwise valid.
    #[test]
    fn a_chain_longer_than_three_is_refused() {
        let deep = ["attestation-ca", "piv-ca", "piv-ca-deep"].map(forged);
        chain_to_anchor(&forged("f9-deep"), Start::Intermediate, &[forged("root")], &deep, None, 4).unwrap();
        assert_fires(&verify_forged("slot-deep", "f9-deep", &["piv-ca-deep"]), Check::ChainLength);

        link(&forged("slot-sub"), Start::EndEntity, &forged("device-sub"), None).unwrap();
        link(&forged("device-sub"), Start::Intermediate, &forged("f9"), None).unwrap();
        assert_fires(&verify_forged("slot-sub", "f9", &[]), Check::AttestPivSlotByDevice);
        assert_fires(&verify_forged("slot-sub", "device-sub", &["f9"]), Check::ChainLength);
    }

    /// The fuzz target's input format reaches the whole chain. The fixture chain, with the length
    /// prefix that `nix/fuzz.nix` uses to seed it, verifies. A short or truncated input is refused
    /// with an error and never causes a panic.
    #[test]
    fn the_fuzz_entry_point_reads_the_fixture_chain() {
        let (slot, device) = (der_of("slot.pem"), der_of("f9.pem"));
        let input = [&u16::try_from(slot.len()).unwrap().to_be_bytes()[..], &slot, &device].concat();
        fuzz_piv_attestation(&input, &[], &[]).unwrap();
        assert!(fuzz_piv_attestation(&input[..1], &[], &[]).is_err());
        assert!(fuzz_piv_attestation(&input[..40], &[], &[]).is_err());
    }

    /// Under `check`, every certificate of the chain must be within its validity period
    /// (ISSUES.md B8). The fixture chain is valid from 2026-11-12 to 2036-11-09, so it verifies in
    /// 2030 and is a conflict before and after that period, and the error names the time and the
    /// period. Without a time (`--ignore-validity`), the dates are not read. Every other verb only
    /// warns: outside its dates, the chain verifies, and the failure about the dates becomes the
    /// warning (`ChainTime::Warn`).
    #[test]
    fn check_holds_the_chain_to_its_dates() {
        let anchors = pem_certs(&String::from_utf8(fixture("root.pem")).unwrap()).unwrap();
        let at = |s: &str| s.parse::<DateTime>().unwrap().unix_duration().as_secs();
        let verify = |t| {
            verify_piv_attestation(&der_of("slot.pem"), &der_of("f9.pem"), &anchors, &[], &spki_of("slotpub.pem"), t)
        };
        verify(Some(at("2030-01-01T00:00:00Z"))).unwrap();
        for t in ["2020-01-01T00:00:00Z", "2040-01-01T00:00:00Z"] {
            let err = verify(Some(at(t))).unwrap_err();
            assert!(
                matches!(err, KmError::Conflict(_)) && err.to_string().contains(&format!("is not valid at {t}")),
                "{err}"
            );
            assert!(err.to_string().contains("--ignore-validity"), "{err}");
        }
        verify(None).unwrap();
        let late = at("2040-01-01T00:00:00Z");
        let (_, warning) = cakeys_pkcs11::ChainTime::Warn(late).verify(verify).unwrap();
        assert!(warning.as_deref().is_some_and(|w| w.contains("is not valid at 2040-01-01T00:00:00Z")), "{warning:?}");
        assert!(cakeys_pkcs11::ChainTime::At(late).verify(verify).is_err());
        let on_time = cakeys_pkcs11::ChainTime::Warn(at("2030-01-01T00:00:00Z")).verify(verify).unwrap();
        assert_eq!(on_time.1, None);
    }
}
