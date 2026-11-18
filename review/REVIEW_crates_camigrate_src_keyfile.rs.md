# Review: crates/camigrate/src/keyfile.rs (691 lines)

Reviewed 2026-11-18 [read]. Summary: reads the file an object is born in (docs/FILE.md F4). It
takes PEM blocks or sniffed DER: PKCS#8, PKCS#1, SEC1, encrypted PKCS#8, PKCS#12, certificates,
SPKI, and secret-key values as raw, hex or base64. Every private key is normalised to PKCS#8 in
zeroized buffers, sized so the key is never copied by a reallocation. Well-structured and well
tested against OpenSSL fixtures. One real gap: the "does this file hold a private key" gate and
the parser read PEM differently.

## Findings

### F1. The plaintext gate and the PEM parser disagree on what a PEM block is — risk

**Verification:** confirmed. `holds_private_key` needs a line that `starts_with("-----BEGIN ")` (keyfile.rs:110), while `pem_entries` slices from `rest.find("-----BEGIN ")` anywhere (:301-302) and decodes `PRIVATE KEY` blocks to PKCS#8 (:318) before `certificate`/`public_key` look at them, so an indented or same-line `-----BEGIN PRIVATE KEY-----` is decoded without `--allow-host-plaintext` (lib.rs:1389). [read]
`crates/camigrate/src/keyfile.rs:109-111` (`holds_private_key`: a line *starting* with
`-----BEGIN` and containing `PRIVATE KEY`) against `:301-309` (`pem_entries`: `-----BEGIN`
*anywhere*). Example: a file whose `-----BEGIN PRIVATE KEY-----` follows other text on its line
(a mangled paste, or a header written on the same line). `holds_private_key` says no, so
`from_its_file` (lib.rs:1389) imports a certificate or public key object without
`--allow-host-plaintext`. `pem_entries` then decodes the key, and `certificate()`/`public_key()`
derive its public half, so the plaintext is in memory without the flag. Derive the gate from the
same scan, i.e. a label-only pass of `pem_entries`' loop. [read]

**Fixed (2026-11-18):** the gate reads the same scan the reader decodes by (`pem_blocks`,
`der_kind`); an unsplittable PEM file is taken to hold a key. Test:
`the_gate_sees_every_key_the_reader_decodes` (five manglings of every fixture).

### F2. Any PKCS#8 decoding error is reported as a type mismatch — nit

`crates/camigrate/src/keyfile.rs:86-88`. `spki_of_pkcs8(&pkcs8).map_err(|_| …)` throws away the
error. A malformed RSA key or an unsupported algorithm is reported as "does not read as a key of
the object's type", sending the user after the wrong problem. Keep the type-mismatch text for
the SEC1 curve case it was written for (the comment at `:85`) and append the original error. [read]

## Design

- Two places decide whether bytes are a private key: `holds_private_key` and `entries`/`der_entry`.
  They should be one function returning the labels or kinds found, so the plaintext gate cannot
  drift from the parser (F1).

## Checked, no issue

- `wrap`/`tlv`: `body`'s capacity covers its headers (≤ 15 bytes beyond the key and algorithm),
  and `out`'s 8 covers a length up to 2⁴⁸. So no reallocation leaves an unzeroized copy of the
  key at real key sizes.
- `detect`: the or-pattern with a guard tries hex, then base64 (Rust evaluates the guard per
  alternative). The raw-length check runs first on the untouched bytes, as FILE.md says.
- SEC1: a named curve must be one cakeys knows. A SEC1 key with no named curve takes the object's
  curve (never an Edwards one). A key on another curve is refused by `check_type`.
- PKCS#1: only two-prime (nine INTEGERs, version 0). Multi-prime is refused by name.
- Legacy encrypted PEM, OpenSSH keys and `RSA PUBLIC KEY` are refused, each with its conversion
  command. Unknown labels are 17, and parameter blocks are skipped.
- Every private-key buffer (`der`, `Entry::Key`, `Material::bytes`, the decoded secret
  spellings) is `Zeroizing`.
