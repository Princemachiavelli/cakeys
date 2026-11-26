# cakeys in diagrams

This document draws the levels, verbs and rules of [`DESIGN.md`](DESIGN.md) as diagrams. Where
the two documents differ, DESIGN.md is authoritative. All diagrams are
[Mermaid](https://mermaid.js.org) diagrams, which GitHub renders inline.

## 1. The three levels, and the files that hold them

`keys.toml` is the declarative input, and cakeys never writes it. `keys.lock` is the file in
which cakeys records what it found, and cakeys updates it in place. A spec is a policy *about*
an object. A realisation is the record of a spec's object on one token.

```mermaid
flowchart LR
    subgraph TOML["keys.toml: the input, which cakeys never writes"]
        direction TB
        T["[tokens.&lt;name&gt;]<br/>module · provider · tokenLabel · pinFile/pinEnv · soCredentialFile/soCredentialEnv ·<br/>options (the provider's own) · probe · migrate · nix (each read by one tool)"]
        O["[objects.&lt;name&gt;]<br/>class · keyType · certificateType ·<br/>curve / modulusBits / valueLen"]
        S["[specs.&lt;name&gt;]<br/>object: exactly one object<br/>attributes · publicAttributes<br/>tokens.&lt;t&gt;: locator · origin ·<br/>publicOnly · binding · attestation"]
        S -- references --> O
    end

    subgraph LOCK["keys.lock: version = 1 (a draft), updated in place"]
        direction TB
        LO["[objects.&lt;name&gt;]<br/>type · commitmentLabel · pairs<br/>ids: scheme → sha256-… (SRI)"]
        LR["[realisations.&lt;spec&gt;.&lt;token&gt;]<br/>compared: object · locator · specDigest · mode ·<br/>schemes · publicOnly · binding · attestation · policy · immutables<br/>observed: uri · session<br/>observation: the key of an [observations] entry<br/>(provider · cakeysVersion · profile · module · token · mechanisms)<br/>provenance: origin"]
        LR -- "object and schemes name it" --> LO
    end

    O -- "the material, hashed into the IDs,<br/>and the intrinsic type they were computed for" --> LO
    S -- "one realisation per (spec, token)" --> LR
```

- Several specs may share one object, and each of them applies a different policy to the same
  material. A spec has exactly one realisation per token.
- The lock's `ids` record *what the material is*. The realisations record *where the material
  is and under which policy*.
- Each object's entry is self-contained, so lock files can be split and joined per object.
  `pairs` records which objects share a public key (a key and its certificate, or a private and
  a public key object), so that these relations survive a split.

## 2. The steps of a verb: `create` (PUT) and `lock`

Every use computes the identity again from the token and compares it with the lock. Only
`create` makes the object, and only when the locator is empty. `lock` finds the object or exits
with 11. Both verbs record a first use in the lock by default. With `lock --dry-run` or
`create --no-update-lock` (and always in `check`), a first use fails in the way that a
fixed-output derivation fails: the run prints the hash to record.

```mermaid
flowchart TD
    START(["cakeys create | lock &lt;object&gt; [--spec &lt;s&gt;] [--token &lt;t&gt;]"]) --> GUARD
    GUARD["a writing run (the default) takes the exclusive lock<br/>on &lt;lock&gt;.lck for the whole run"]
    GUARD -- "no lock file, and no --new-lock" --> X17L(["exit 17: the lock file does not exist"])
    GUARD -- "inside the Nix build sandbox, or the lock<br/>is not writable" --> X21(["exit 21 before any token is touched:<br/>pass --dry-run"])
    GUARD --> VAL["validate: the mode, the binding, the shapes of the attributes,<br/>certificateType, and the names for each class"]
    VAL -- "invalid spec" --> X17(["exit 17"])
    VAL --> FIND["find by locator<br/>(CKA_LABEL, CKA_ID)"]
    FIND -- "several objects match" --> X12(["exit 12 ambiguous"])
    FIND -- "absent, for lock" --> X11(["exit 11 not found"])
    FIND -- "absent, for create" --> PIN{"does the lock already pin this<br/>object's material? (D1)"}
    PIN -- "yes: a new generation could<br/>never match" --> X14b(["exit 14: put the same material under<br/>the locator, or give the key a new object name"])
    PIN -- no --> CREATE["create into the empty locator only<br/>(If-None-Match)"]
    FIND -- "found (for create, exit 19 unless the lock pins it),<br/>or just created" --> RESOLVE
    CREATE --> RESOLVE["resolve: read the type, the policy and the material ·<br/>compute the CA-IDs (schemes, strongest first) ·<br/>for a private key, prove possession"]
    RESOLVE -- "the proof does not verify" --> X13a(["exit 13 conflict"])
    RESOLVE -- "the token refuses or lacks the mechanism" --> X15(["exit 15 unsupported"])
    RESOLVE --> RECONCILE{"compare with the lock"}
    RECONCILE -- "first use, and the lock is not written<br/>(lock --dry-run, create --no-update-lock)" --> X18(["exit 18 first use; prints got: sha256-…"])
    RECONCILE -- "an ID differs" --> X10b(["exit 10 hash mismatch,<br/>also when the lock is written"])
    RECONCILE -- "without a write: the object, locator, spec digest or policy changed;<br/>always: a changed type, a weaker mode, binding or scheme set,<br/>or a weakened immutable" --> X14(["exit 14: review the change, then lock again;<br/>a downgrade or a replaced object is refused even then"])
    RECONCILE -- "it matches, or a first use (default)" --> OK(["the resolved JSON is printed; exit 22 when<br/>the run recorded what the lock lacked,<br/>0 when the lock was already complete"])
```

`check` runs the same steps without the write, in a read-only session, and prints the URI.
Every verb except `validate` and `gc` takes an address that names the object first
(`<object> [--spec] [--token]`). `delete` proves possession again, so that its If-Match
condition cannot pass on an unrelated object that sits under the locator. `gc` prints the lock
entries that the config no longer names and removes them (with `--dry-run`, it only prints
them).

## 3. Proof of possession: which `binding` applies

A private key's identity is the hash of a public key, and that public key may come from a
*separate* object. So every resolve proves again that the private key under the locator belongs
to that public key. It uses whichever capability the key has.

```mermaid
flowchart TD
    K(["private key, CKO_PRIVATE_KEY"]) --> PO{"publicOnly?"}
    PO -- "yes: adopt through the public object,<br/>with no login (no PIV PIN retry is used)" --> TA(["binding = token-asserted<br/>(publicOnly implies it, and the lock records it)"]);
    PO -- no --> B{"tokens.&lt;t&gt;.binding"}
    B -- "unset: pop-sign" --> S{"is CKA_SIGN = true declared?"}
    S -- no --> X(["exit 17: declare the capability,<br/>choose a matching pop-*, or opt out<br/>with token-asserted"])
    S -- yes --> PS(["the token signs a fresh challenge:<br/>ECDSA-SHA*, CKM_EDDSA, or RSA v1.5 or PSS,<br/>as the key's mechanisms allow; the host verifies<br/>the signature against the SPKI"])
    B -- pop-ecdh --> D{"CKK_EC (not Edwards)<br/>and CKA_DERIVE = true?"}
    D -- no --> X
    D -- yes --> PE(["the host makes an ephemeral key and MACs the challenge<br/>with the ECDH secret; the token derives the secret with<br/>CKM_ECDH1_DERIVE into a non-extractable session key<br/>and MACs with CKM_SHA256_HMAC; the MACs are compared.<br/>A token that refuses this derives a readable secret,<br/>which the host compares with its own"])
    B -- pop-decrypt --> E{"CKK_RSA<br/>and CKA_DECRYPT = true?"}
    E -- no --> X
    E -- yes --> PD(["the host encrypts a fresh secret with RSA-OAEP<br/>(SHA-1, then SHA-256, then SHA-512 when the token<br/>refuses the hash at init), or with RSA v1.5 padding<br/>when only CKM_RSA_PKCS is usable;<br/>the token decrypts it, and the plaintexts<br/>are compared in constant time"])
    B -- token-asserted --> TA2(["no proof: only the token's report<br/>links the private key to the public key.<br/>A later change from any pop-* to this<br/>binding is refused (exit 14)"])
```

All `pop-*` bindings have the same, highest rank, because each of them proves possession of the
same key. The diagram does not show `pop-unwrap`, which proves possession of an RSA key that may
only unwrap (a transport key, CAMIGRATE.md D3): the host wraps a fresh secret to the public key
with RSA-OAEP, the token unwraps it into a non-extractable session key, and both sides MAC the
challenge with it. A key with `CKA_ALWAYS_AUTHENTICATE` signs after a context-specific login with
the session's PIN, and the lock records `pop-sign-pin` for it ([DESIGN.md](DESIGN.md) §3.6).

## 4. Identity: one object, several schemes

The lock may hold several IDs per object, one per *scheme*, and each ID is an SRI digest. A
scheme never changes once it is defined (§10 of DESIGN): a changed computation gets a new scheme
name. `Scheme::DEPRECATED` lists the deprecated schemes, and it is empty today.

```mermaid
flowchart LR
    PK["private and public keys"] --> R["rfc7093m4<br/>SHA-256 of the canonical SPKI,<br/>verified on the host"]
    C["certificates<br/>(CKC_X_509)"] --> CH["certhash<br/>SHA-256 of the DER"]
    C --> R
    D["data objects"] --> VH["valuehash<br/>SHA-256 of CKA_VALUE<br/>(equal to Nix's flat fixed-output hash)"]
    G["generic secret,<br/>CKK_SHA*_HMAC"] --> COM["commitment<br/>HMAC over the label,<br/>with the key type's hash"]
    A["AES<br/>(DES3: kcv-ecb and kcv-ecb-dec only)"] --> CM["cmac"]
    CM -- weaker --> K1["kcv-ecb"]
    K1 -- weaker --> K2["kcv-ecb-dec"]
    K2 -- weaker --> KW["kw"]
    YK["YubiKey PIV keys<br/>(opt-in, §3.7)"] -. "per realisation,<br/>beside rfc7093m4" .-> PA["piv-attestation<br/>a digest of what the slot's certificate<br/>asserts, verified to the<br/>pinned Yubico root"]
    TP["tpm2-pkcs11 keys<br/>(opt-in, §3.7)"] -. "per realisation,<br/>beside a portable scheme" .-> TC["tpm-certify<br/>TPM2_Certify over the Name,<br/>with a fresh nonce, verified on the host<br/>against the pinned AK"]
    style CM fill:#dfe
    style KW fill:#fdd
    style PA fill:#fed
    style TC fill:#fed
```

Only the usage attributes that the spec declares decide which commitment schemes run
(`CKA_SIGN` → `cmac`, `CKA_ENCRYPT` → `kcv-ecb`, …). The first scheme computed is the primary
scheme. The lock stores only the SHA-256 of the token's output, never a MAC or a ciphertext
under the key. The attestation schemes (`attestation = true`) record the provenance of the key on
one device, and they are not a portable identity: the same material on another token attests
differently or not at all. So each attestation is recorded on its own realisation, beside a
portable scheme, and the portable scheme is what links the copies on different tokens.

## 5. Usage: the Nix loop

```mermaid
flowchart LR
    KT["keys.toml"] --> MK["lib.mkKeys { cakeys }"]
    KL["keys.lock"] --> MK
    MK -->|"keys.&lt;object&gt; { token, spec, scheme }<br/>→ type · id · spec · token · requiredSystemFeatures · check"| DRV["consumer derivation"]
    DRV -->|"requiredSystemFeatures =<br/>[ token-&lt;name&gt; ]"| HOOK["Nix pre-build hook<br/>(nix/sandbox-hook.sh)"]
    HOOK -->|"grants the token's device or socket<br/>only to the builds that require its feature"| SB["build sandbox"]
    SB --> CHK["the check command: cakeys check,<br/>against id.&lt;scheme&gt;"]
    CHK -->|"first use (a key that cakeys create made<br/>outside the build): fails with got: sha256-…"| OOB["record it outside the build:<br/>cakeys lock"]
    OOB -.-> KL
    CHK -->|"every later build: the CA-ID<br/>is computed again and compared"| URI["the pkcs11: URI on stdout"]
```

The only tokens that a real build may reach are a p11-kit forwarding socket and a real TPM
(`/dev/tpmrm0`). A build never reaches a token database, because its files would allow offline
PIN guessing.
