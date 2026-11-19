# TPM manufacturer trust anchors

The pinned roots an endorsement key (EK) certificate is verified to before cakeys activates a
credential with that EK (`attest/credential.rs`, docs/DESIGN.md §3.7). A verified chain and the
activation prove that the Attestation Key resides in a TPM the manufacturer certified. Without
them the AK is trusted on first use. `tokens.<t>.options.ekRoots` adds anchors for other
manufacturers, and the tests use it for their own CA.

| File | Role | Source |
|---|---|---|
| `amd-ftpm-rsa-root.pem` | "AMDTPM" (RSA-2048, self-signed, valid until 2039-10-23): signs the "PRG-*" intermediates of AMD fTPM RSA EK certificates | AMD KDS: the authorityInfoAccess of the PRG-RN intermediates (`http://ftpm.amd.com/pki/aia/…`) |
| `amd-ftpm-ecc-root.pem` | "AMDTPM" (P-256, self-signed, valid until 2041-01-01): signs the "PRG-*" intermediates of AMD fTPM ECC EK certificates | as above |

SHA-256 fingerprints of the DER certificates:

- RSA: `67:BD:24:72:A5:46:75:1C:AC:A5:F3:58:A7:8F:80:72:75:31:67:13:38:96:0A:9B:CF:DF:BE:6A:34:D0:C6:A1`
- ECC: `14:AA:C9:FD:58:47:1A:61:2A:FD:75:D8:C0:95:5D:AF:99:F0:91:B1:86:37:02:F9:E0:D4:11:3F:AF:23:4F:9D`

## How they were obtained and checked (2026-11-18)

AMD fTPMs keep no EK certificate in NV. AMD serves each one from its key distribution server,
by a URL derived from the EK's public key (`tpm2_getekcertificate`). The EK certificates of the
development machine's fTPM (`../tests/fixtures/amd-ftpm-ek-{rsa,ecc}.pem`, each the leaf and
then its PRG-RN intermediate) were fetched that way. The intermediates and these roots came from
each certificate's authorityInfoAccess, over HTTP. For each algorithm, `openssl verify` accepts
leaf ← PRG-RN ← AMDTPM, and the leaf's public key is the EK the TPM recreates from the TCG
default template.

These roots were fetched over HTTP, so they were also checked against a source that did not
come through that connection. Microsoft's `TrustedTpm.cab` (<https://go.microsoft.com/fwlink/?linkid=2097925>,
the bundle Windows uses for EK attestation) ships `AMD-fTPM-RSA-RNFamily.crt` and
`AMD-fTPM-ECC-RNFamily.crt`. Those are PRG-RN intermediates with other serials and keys than
this machine's issuer, and each verifies under the matching root here. So the roots' keys are
the keys that sign the AMD fTPM intermediates Microsoft distributes. The bundle does not carry
the AMDTPM roots themselves.

Not pinned: AMD's other EK hierarchies in that bundle ("AMD fTPM EK Root E3/R2", Pluton). Pin
them the same way when a machine needs them, or name them with `ekRoots`.

`../build.rs` pins each file's SHA-256, so a file that differs fails the build. The unit test
`the_amd_ftpm_chains_verify_to_the_pinned_roots` verifies both committed EK chains to them.
Updating this directory is a deliberate diff of both.
