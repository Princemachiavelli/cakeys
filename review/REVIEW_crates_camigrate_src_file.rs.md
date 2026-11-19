# Review: crates/camigrate/src/file.rs (422 lines)

Reviewed 2026-11-18 [read]. Summary: passphrase-protected key files. It writes encrypted PKCS#8
(PBES2: PBKDF2-SHA256 600k, AES-256-CBC) and PKCS#12 (the same shrouded key beside the
certificate, HMAC-SHA256 MAC). It reads them back, verifying the MAC with a constant-time compare
before decrypting, bounding every KDF, and refusing legacy schemes with a re-export hint.
Careful code with good tests. The findings are minor.

## Findings

### F1. docs/CAMIGRATE.md still gives the old MAC iteration count — nit

`crates/camigrate/src/file.rs:25` (`MAC_ITERATIONS = 600_000`, the B10 fix) against
docs/CAMIGRATE.md:234, "HMAC-SHA256 MAC (PKCS#12 KDF, 10 000 iterations)". The frozen-format
section describes files camigrate no longer writes. [read]

**Fixed (2026-11-18):** CAMIGRATE.md gives 600 000 iterations for the MAC, as many as for the key.

### F2. KDF work is bounded per KDF, not per file — nit

`crates/camigrate/src/file.rs:185-187`. Each `encryptedData` container is decrypted with up to
`MAX_ITERATIONS` (10M PBKDF2) or the scrypt cap, and a PKCS#12 may hold any number of them.
This only happens after the MAC verifies, so it needs the passphrase. Someone who has it can
make a file take N × (seconds) to open. A total budget across the file, or a cap on containers
(OpenSSL writes two), would close it. [read]

**Fixed (2026-11-18):** a PKCS#12 with more than `MAX_ENCRYPTED_CONTAINERS` (2) encrypted
containers is refused (17) before any of their KDFs runs, so a file's KDF work is at most its
MAC's, two containers' and its key's. Test: `key_files_of_another_shape_are_refused`.

### F3. Certificate bags are not checked to be X.509 — nit

`crates/camigrate/src/file.rs:194-196`. `cert_id` is not compared with
`PKCS_12_X509_CERT_OID`, so an `sdsiCertificate` bag is taken as DER. It then fails at
`id::cert_spki`/`key_certificate` with a parse message rather than "not an X.509 certificate
bag". [read]

**Fixed (2026-11-18):** a certificate bag whose `certId` is not X.509 is refused (17) by name.
Test: `key_files_of_another_shape_are_refused`.

### F4. An encrypted PKCS#8 PEM is recognised only at byte 0 — nit

`crates/camigrate/src/file.rs:162`. A leading BOM, blank line or OpenSSL `Bag Attributes` text
sends the file to the PKCS#12 parser, which fails with "neither an encrypted PKCS#8 PEM nor
PKCS#12". keyfile.rs finds PEM blocks anywhere. `import --in` could use the same scanner. [read]

**Fixed (2026-11-18):** `read` takes PEM text by `keyfile::pem_text`/`pem_blocks`, the scanner an
object's own file is read by: one `ENCRYPTED PRIVATE KEY` block wherever it starts; another
label, or several blocks, is refused by name. Test: `an_encrypted_pem_reads_wherever_its_block_starts`.

## Design

- Two readers of encrypted keys: `file::read` for `--in` (encrypted PKCS#8 PEM or PKCS#12 only)
  and `keyfile::read` for objects' own files (every format, and it calls into here). `--in` could
  go through `keyfile` with a "private key" object type and lose the format split (F4).

## Checked, no issue

- ISSUES.md B10 (Done): the MAC key derivation uses 600,000 iterations, matching the encryption
  (`:25`, `:123`, `:133`).
- ISSUES.md B19 (Done): scrypt is refused when N × r > 2²³ or p > 16, checked on the PKCS#8 key
  bag (`decrypt`) and on the encrypted certificate container (`encrypted_octets`), before any
  KDF runs. PBKDF2 over 10M iterations is refused the same way, and the MAC iteration count is
  range-checked from `i32` to 1..=10M before deriving.
- The MAC is compared with `ct_eq`. A wrong passphrase is 17 (`wrong()`), never 10.
- Zeroization: the derived MAC key and the decrypted PKCS#8 are `Zeroizing`, and nothing
  formats a key or the passphrase. Decrypted certificate containers hold only encrypted key
  bags, never plaintext keys.
- Writing: a fresh salt and IV per file, and the key bag and certificate bag share `localKeyId`.
