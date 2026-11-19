//! Which endorsement key the AK is proven against (review D5): the EK certificate the token names
//! (`ekCertificate`), else the one the TPM keeps in NV, verified to a manufacturer root. With
//! one, the attestation's anchor is that root and every attestation activates a credential to
//! the EK (`esys::activate`); without one, the AK is trusted on first use, as before.

use super::Tpm2Options;
use super::esys;
use cakeys_core::chain::{Cert, Start, certs_of, chain_to_anchor, pem_certs};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ChainTime;
use std::sync::LazyLock;
use tss_esapi::Context;

/// The manufacturer roots built in (roots/README.md), pinned by build.rs.
static ROOTS: LazyLock<Vec<Cert>> = LazyLock::new(|| {
    let mut roots =
        pem_certs(include_str!("../../roots/amd-ftpm-rsa-root.pem")).expect("embedded AMD fTPM RSA root parses");
    roots.extend(
        pem_certs(include_str!("../../roots/amd-ftpm-ecc-root.pem")).expect("embedded AMD fTPM ECC root parses"),
    );
    roots
});

/// The CA links an EK chain may have above the EK certificate: a manufacturer's root, its
/// per-product intermediate, and one more for the hierarchies that split by plant.
const MAX_LINKS: u8 = 3;

/// A verified EK certificate: the EK's public key, and the anchor its chain reached.
pub(crate) struct Trusted {
    /// The canonical SPKI of the EK the certificate is for.
    pub(crate) spki: Vec<u8>,
    /// The canonical SPKI of the anchor: what the lock pins as the attestation's root.
    pub(crate) anchor_spki: Vec<u8>,
    /// The chain's dated failure, accepted under [`ChainTime::Warn`].
    pub(crate) warning: Option<String>,
}

/// The EK to prove the AK against, when there is one to trust.
///
/// `ekCertificate` (a PEM bundle, leaf first, or one DER certificate) must verify to a built-in
/// root or one of `ekRoots`, or the attestation is refused: naming a certificate demands it. A
/// certificate only found in NV that reaches no anchor (a manufacturer cakeys pins no root for,
/// or one whose intermediates NV does not hold) leaves the AK trusted on first use, as a TPM
/// with no certificate does.
///
/// # Errors
///
/// `Unavailable` when a named file cannot be read or NV cannot be; `Validation` when a named file
/// holds no certificate; `Conflict` when `ekCertificate` does not verify; whatever the chain's
/// dates refuse under `time`.
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

/// An EK certificate read from NV: first use (`None`) only when its chain links to no anchor at
/// all. One that links but fails its dates is that failure, as for `ekCertificate`, so `check`
/// never reports it as an anchor that changed.
fn from_nv(leaf: &Cert, anchors: &[Cert], time: ChainTime) -> Result<Option<Trusted>> {
    if verify(leaf, anchors, &[], ChainTime::Unchecked).is_err() {
        return Ok(None);
    }
    verify(leaf, anchors, &[], time).map(Some)
}

/// `leaf` verified to one of `anchors` through `pool`, its dates judged by `time`.
fn verify(leaf: &Cert, anchors: &[Cert], pool: &[Cert], time: ChainTime) -> Result<Trusted> {
    let (anchor_spki, warning) =
        time.verify(|at| chain_to_anchor(leaf, Start::EndEntity, anchors, pool, at, MAX_LINKS)?.spki())?;
    Ok(Trusted { spki: leaf.spki()?, anchor_spki, warning })
}

/// The certificates in the file an option names.
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

    /// The development machine's AMD fTPM EK certificates (tests/fixtures, fetched from AMD's
    /// key distribution server), each with its PRG-RN intermediate, verify to the built-in roots
    /// at a time within their validity, and name the root of their own algorithm.
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
            // Without the intermediate, or with only the other algorithm's root, nothing verifies.
            assert!(verify(&leaf, &ROOTS, &[], at).is_err());
            let other = Cert::from_der(ROOTS[1 - root].der().to_vec()).unwrap();
            assert!(verify(&leaf, std::slice::from_ref(&other), &pool, at).is_err());
        }
    }

    /// A NV certificate whose chain reaches no anchor is first use; one whose chain reaches an
    /// anchor but is out of its dates is refused under a `check` time, warned of otherwise.
    /// (The AMD fixture's intermediate stands in as the anchor of a NV certificate.)
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

    /// The roots are the files roots/README.md records: their SPKI digests (what a lock pins as
    /// the attestation's root, computed with openssl) pinned here as well as their file hashes in
    /// build.rs, so a substituted root fails twice.
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
