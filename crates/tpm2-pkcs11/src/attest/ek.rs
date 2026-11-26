//! The choice of the endorsement key against which the AK is proven (review D5). It is the EK
//! certificate that the token names (`ekCertificate`), or otherwise the certificate that the TPM
//! keeps in NV, verified to a manufacturer root. With such a certificate, the attestation's
//! anchor is that root, and every attestation activates a credential to the EK
//! (`esys::activate`). Without one, the AK is trusted on first use, as before.

use super::Tpm2Options;
use super::esys;
use cakeys_core::chain::{Cert, Start, TCG_KP_EK_CERTIFICATE, certs_of, chain_to_anchor, pem_certs};
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::ChainTime;
use std::sync::LazyLock;
use tss_esapi::Context;

/// The built-in manufacturer roots (roots/README.md), which build.rs pins.
static ROOTS: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    let mut roots =
        pem_certs(include_str!("../../roots/amd-ftpm-rsa-root.pem")).expect("embedded AMD fTPM RSA root parses");
    roots.extend(
        pem_certs(include_str!("../../roots/amd-ftpm-ecc-root.pem")).expect("embedded AMD fTPM ECC root parses"),
    );
    roots
});

/// The number of CA links that an EK chain may have above the EK certificate: a manufacturer's
/// root, its intermediate for each product, and one more for the hierarchies that split by
/// plant.
const MAX_LINKS: u8 = 3;

/// A verified EK certificate: the EK's public key, and the anchor that its chain reached.
pub(crate) struct Trusted {
    /// The canonical SPKI of the EK the certificate is for.
    pub(crate) spki: Vec<u8>,
    /// The canonical SPKI of the anchor, which the lock pins as the attestation's root.
    pub(crate) anchor_spki: Vec<u8>,
    /// The chain's failure of a date check, accepted under [`ChainTime::Warn`].
    pub(crate) warning: Option<String>,
}

/// Returns the EK against which the AK is proven, when there is an EK to trust.
///
/// `ekCertificate` (a PEM bundle with the leaf first, or one DER certificate) must verify to a
/// built-in root or to one of `ekRoots`, or the attestation is refused, because naming a
/// certificate requires it to verify. A certificate that is found only in NV and reaches no
/// anchor (from a manufacturer for which cakeys pins no root, or whose intermediates NV does not
/// hold) leaves the AK trusted on first use, as for a TPM with no certificate.
///
/// # Errors
///
/// Returns `Unavailable` when a named file or NV cannot be read, `Validation` when a named file
/// holds no certificate, and `Conflict` when `ekCertificate` does not verify. Also returns the
/// error for a chain whose dates `time` refuses.
pub(crate) fn trusted(token: &str, opts: &Tpm2Options, time: ChainTime, esys: &mut Context) -> Result<Option<Trusted>> {
    let mut anchors: Vec<Cert> = ROOTS.iter().map(|c| Cert::from_der(c.der().to_vec())).collect::<Result<_>>()?;
    if let Some(path) = &opts.ek_roots {
        anchors.extend(read_certs(token, "ekRoots", path)?);
    }
    if let Some(path) = &opts.ek_certificate {
        let mut certs = read_certs(token, "ekCertificate", path)?.into_iter();
        let leaf = certs.next().ok_or_else(|| empty(token, "ekCertificate", path))?;
        let pool: Vec<Cert> = certs.collect();
        return verify(&leaf, &anchors, &pool, time)
            .map(Some)
            .map_err(|e| e.prefixed(format_args!("tokens.{token}.options.ekCertificate ({path})")));
    }
    match esys::nv_ek_certificate(esys)?.and_then(|der| Cert::from_der(der).ok()) {
        Some(leaf) => from_nv(&leaf, &anchors, time),
        None => Ok(None),
    }
}

/// Verifies an EK certificate that was read from NV. Returns `None` (trust on first use) only
/// when its chain links to no anchor at all. A chain that links to an anchor but fails its date
/// checks returns that failure, as for `ekCertificate`, so `check` never reports it as an anchor
/// that changed.
fn from_nv(leaf: &Cert, anchors: &[Cert], time: ChainTime) -> Result<Option<Trusted>> {
    if verify(leaf, anchors, &[], ChainTime::Unchecked).is_err() {
        return Ok(None);
    }
    verify(leaf, anchors, &[], time).map(Some)
}

/// Verifies `leaf` to one of `anchors` through `pool`, with its dates judged by `time`. A leaf
/// that names its purposes must name the EK purpose (`tcg-kp-EKCertificate`), because another
/// certificate that the same CA issued is not an EK credential (review 2026-11-23 A-3).
fn verify(leaf: &Cert, anchors: &[Cert], pool: &[Cert], time: ChainTime) -> Result<Trusted> {
    if !leaf.serves(&TCG_KP_EK_CERTIFICATE)? {
        return Err(KmError::Conflict(Reason::check(
            Check::AttestTpmEkCertificate,
            "the EK certificate's extendedKeyUsage does not name tcg-kp-EKCertificate (2.23.133.8.1): it is \
             no Endorsement Key credential",
        )));
    }
    let (anchor_spki, warning) =
        time.verify(|at| chain_to_anchor(leaf, Start::EndEntity, anchors, pool, at, MAX_LINKS)?.spki())?;
    Ok(Trusted { spki: leaf.spki()?, anchor_spki, warning })
}

/// Returns the certificates in the file that an option names.
fn read_certs(token: &str, option: &str, path: &str) -> Result<Vec<Cert>> {
    let file = super::expand_home(path);
    let bytes = std::fs::read(&file)
        .map_err(|e| KmError::Unavailable(format!("tokens.{token}.options.{option}: reading {file}: {e}").into()))?;
    let certs = certs_of(&bytes).map_err(|e| e.prefixed(format_args!("tokens.{token}.options.{option} ({file})")))?;
    if certs.is_empty() {
        return Err(empty(token, option, path));
    }
    Ok(certs)
}

fn empty(token: &str, option: &str, path: &str) -> KmError {
    KmError::Validation(format!("tokens.{token}.options.{option} ({path}) holds no certificate").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AMD fTPM EK certificates of the development machine (tests/fixtures, fetched from
    /// AMD's key distribution server), each with its PRG-RN intermediate, verify to the built-in
    /// roots at a time within their validity, and each names the root of its own algorithm.
    #[test]
    fn the_amd_ftpm_chains_verify_to_the_pinned_roots() {
        let at = ChainTime::At(1_800_000_000); // 2027-01-15
        for (bundle, root) in [
            (&include_bytes!("../../tests/fixtures/amd-ftpm-ek-ecc.pem")[..], 1),
            (&include_bytes!("../../tests/fixtures/amd-ftpm-ek-rsa.pem")[..], 0),
        ] {
            let mut certs = certs_of(bundle).unwrap().into_iter();
            let leaf = certs.next().unwrap();
            let pool: Vec<Cert> = certs.collect();
            let trusted = verify(&leaf, &ROOTS, &pool, at).unwrap();
            assert_eq!(trusted.anchor_spki, ROOTS[root].spki().unwrap());
            assert_eq!(trusted.spki, leaf.spki().unwrap());
            assert!(trusted.warning.is_none());
            // Without the intermediate, or with only the root of the other algorithm, nothing
            // verifies.
            assert!(verify(&leaf, &ROOTS, &[], at).is_err());
            let other = Cert::from_der(ROOTS[1 - root].der().to_vec()).unwrap();
            assert!(verify(&leaf, std::slice::from_ref(&other), &pool, at).is_err());
        }
    }

    /// An EK certificate that names its purposes must name the EK purpose (tcg-kp-EKCertificate).
    /// A TLS server certificate under the same anchor is not an EK credential, whatever its
    /// chain (review 2026-11-23 A-3). The fixtures are the chain-rules chains of the core
    /// crate.
    #[test]
    fn an_ek_certificate_names_the_ek_purpose_or_none() {
        let pem = |bytes: &[u8]| certs_of(bytes).unwrap().remove(0);
        let root = pem(include_bytes!("../../../core/tests/fixtures/chain-rules/ok-root.pem"));
        let anchors = [root];
        for ok in [
            &include_bytes!("../../../core/tests/fixtures/chain-rules/ek-leaf.pem")[..],
            &include_bytes!("../../../core/tests/fixtures/chain-rules/ok-leaf.pem")[..],
        ] {
            verify(&pem(ok), &anchors, &[], ChainTime::Unchecked).unwrap();
        }
        let server = pem(include_bytes!("../../../core/tests/fixtures/chain-rules/server-leaf.pem"));
        let e = verify(&server, &anchors, &[], ChainTime::Unchecked).err().unwrap();
        assert!(e.to_string().contains("does not name tcg-kp-EKCertificate"), "{e}");
    }

    /// This test checks that `verify` refuses an EK certificate chain with more than
    /// [`MAX_LINKS`] signatures, counting the signature on the EK certificate itself. The chain of
    /// `ek-3` has three signatures and verifies. The chain of `ek-4` has four signatures and is
    /// refused, although every certificate in it is valid, and it verifies when its own issuer
    /// `ca-3` is the trust anchor. The script `tests/fixtures/ek-chain/make.sh` generates these
    /// certificates, because review 2026-11-24 L5 found no fixture longer than the limit.
    #[test]
    fn an_ek_chain_longer_than_max_links_is_refused() {
        let pem = |bytes: &[u8]| certs_of(bytes).unwrap().remove(0);
        let root = [pem(include_bytes!("../../tests/fixtures/ek-chain/root.pem"))];
        let pool = [
            pem(include_bytes!("../../tests/fixtures/ek-chain/ca-1.pem")),
            pem(include_bytes!("../../tests/fixtures/ek-chain/ca-2.pem")),
            pem(include_bytes!("../../tests/fixtures/ek-chain/ca-3.pem")),
        ];
        let ek_3 = pem(include_bytes!("../../tests/fixtures/ek-chain/ek-3.pem"));
        let ek_4 = pem(include_bytes!("../../tests/fixtures/ek-chain/ek-4.pem"));
        let at = ChainTime::At(1_800_000_000); // 2027-01-15
        assert_eq!(verify(&ek_3, &root, &pool, at).unwrap().anchor_spki, root[0].spki().unwrap());
        let e =
            verify(&ek_4, &root, &pool, at).err().expect("verify accepted a chain with more than MAX_LINKS signatures");
        let longer = format!("longer than {MAX_LINKS} links");
        assert!(matches!(&e, KmError::Conflict(m) if m.contains(&longer)), "{e}");
        let ca_3 = [Cert::from_der(pool[2].der().to_vec()).unwrap()];
        assert_eq!(verify(&ek_4, &ca_3, &pool, at).unwrap().anchor_spki, ca_3[0].spki().unwrap());
    }

    /// An NV certificate whose chain reaches no anchor means trust on first use. An NV
    /// certificate whose chain reaches an anchor but is outside its dates is refused under a
    /// `check` time, and produces a warning otherwise. (The intermediate of the AMD fixture
    /// serves as the anchor of an NV certificate.)
    #[test]
    fn a_nv_certificate_is_first_use_only_when_it_links_to_nothing() {
        let bundle = certs_of(include_bytes!("../../tests/fixtures/amd-ftpm-ek-ecc.pem")).unwrap();
        let (leaf, intermediate) = (&bundle[0], &bundle[1..]);
        let now = ChainTime::At(1_800_000_000);
        assert!(from_nv(leaf, &ROOTS, now).unwrap().is_none(), "no intermediate in NV: first use");
        assert!(from_nv(leaf, intermediate, now).unwrap().is_some());
        let late = 2_600_000_000; // 2052, after the certificate's notAfter (2046)
        let e = from_nv(leaf, intermediate, ChainTime::At(late)).err().expect("a dated failure is refused");
        assert!(e.to_string().contains("valid"), "{e}");
        let warned = from_nv(leaf, intermediate, ChainTime::Warn(late)).unwrap().unwrap();
        assert!(warned.warning.is_some());
    }

    /// The roots are the files that roots/README.md records. This test pins their SPKI digests
    /// (what a lock pins as the attestation's root, computed with openssl), and build.rs pins
    /// their file hashes, so a substituted root fails twice.
    #[test]
    fn the_amd_ftpm_roots_are_pinned() {
        let sri: Vec<String> = ROOTS.iter().map(|c| cakeys_core::id::sri(&c.spki().unwrap())).collect();
        assert_eq!(
            sri,
            [
                "sha256-iZucnW6SbECq776jkFFz8A97Uq1utNLTLm/LGXlxDis=", // AMDTPM, RSA
                "sha256-XPGFn/vSzRjBM0XUdpK+pOokZPv7dCmDZPqXnoMyKfY=", // AMDTPM, ECC
            ]
        );
    }
}
