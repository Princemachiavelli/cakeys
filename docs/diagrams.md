# cakeys at a glance

Visual companions to [`DESIGN.md`](DESIGN.md), which stays authoritative: the same levels,
verbs and rules, drawn. All diagrams are [Mermaid](https://mermaid.js.org) (GitHub renders them
inline).

## 1. The three levels, and where they live

`keys.toml` is the declarative input; `keys.lock` is what cakeys records and updates in place.
A spec is policy *about* an object; a realisation is one object's life on one token.

```mermaid
flowchart LR
    subgraph TOML["keys.toml — input, never written by cakeys"]
        direction TB
        T["[tokens.&lt;name&gt;]<br/>module · tokenLabel · pinFile/pinEnv · systemFeature"]
        O["[objects.&lt;name&gt;]<br/>class · keyType · certificateType ·<br/>curve / modulusBits / valueLen"]
        S["[specs.&lt;name&gt;]<br/>object → one object only<br/>attributes · publicAttributes<br/>tokens.&lt;t&gt;: locator · autoCreate ·<br/>publicOnly · binding · identity.allow"]
        S -- references --> O
    end

    subgraph LOCK["keys.lock — version = 1 (draft), updated in place"]
        direction TB
        LO["[objects.&lt;name&gt;]<br/>type · commitmentLabel · pairs<br/>ids: scheme → sha256-… (SRI)"]
        LR["[realisations.&lt;spec&gt;.&lt;token&gt;]<br/>compared: object · locator · specDigest · mode ·<br/>schemes · publicOnly · binding · policy · immutables<br/>observed: uri · session · mechanisms<br/>provenance: provider · cakeysVersion · module · token"]
        LR -- "object / schemes name" --> LO
    end

    O -- "material + intrinsic type,<br/>hashed into the ids" --> LO
    S -- "one realisation per (spec, token)" --> LR
```

- Several specs may share one object (different policy over the same material); one spec has
  exactly one realisation per token.
- The lock's `ids` answer *what the material is*; the realisations answer *where it lives and
  under which policy*.
- Objects are self-contained, so lock files split and join per object; `pairs` records the
  key ↔ certificate relations across the split.

## 2. A verb's life: `realise` (PUT)

Every use recomputes the identity from the token and compares it with the lock. First use fails
like a fixed-output derivation: record the printed hash out of band.

```mermaid
flowchart TD
    START(["cakeys realise &lt;spec&gt; --token &lt;t&gt;"]) --> GUARD
    GUARD["--update-lock takes the exclusive lock<br/>on &lt;lock&gt;.lck for the whole run"]
    GUARD --> VAL["validate: mode, binding, attribute shapes,<br/>certificateType, per-class names"]
    VAL -- "invalid spec" --> X17(["exit 17"])
    VAL --> FIND["find by locator<br/>(CKA_LABEL / CKA_ID)"]
    FIND -- "several objects match" --> X12(["exit 12 ambiguous"])
    FIND -- "absent, autoCreate off" --> X11(["exit 11 not found"])
    FIND -- "absent, autoCreate on" --> PIN{"lock already pins this<br/>object's material? (D1)"}
    PIN -- "yes: generation could<br/>never match" --> X14b(["exit 14: same material under<br/>the locator, or a new object name"])
    PIN -- no --> CREATE["create into the empty locator only<br/>(If-None-Match)"]
    FIND -- "found (or just created)" --> RESOLVE
    CREATE --> RESOLVE["resolve: read type · policy · material<br/>compute CA-IDs (schemes, strongest first)<br/>private keys: prove possession"]
    RESOLVE -- "proof does not verify" --> X13a(["exit 13 conflict"])
    RESOLVE -- "token refuses / lacks the mechanism" --> X15(["exit 15 unsupported"])
    RESOLVE --> RECONCILE{"reconcile with the lock"}
    RECONCILE -- "no locked id to compare (first use)" --> X10(["exit 10, prints got: sha256-…"])
    RECONCILE -- "id differs" --> X13b(["exit 13 hash mismatch"])
    RECONCILE -- "object / locator / spec digest / binding /<br/>mode / policy / immutables changed" --> X14(["exit 14: review,<br/>then --update-lock"])
    RECONCILE -- "everything matches" --> OK(["exit 0 — URI printed;<br/>--update-lock records the realisation"])
```

`verify` is the same walk without the create; `check` is `realise` that never writes the lock;
`delete` proves possession once more so If-Match cannot pass on a bystander object; `gc` prints
lock entries the config no longer names and removes them with `--apply`.

## 3. Proof of possession: which `binding` applies

A private key's identity hashes a public key that may come from a *separate* object, so every
resolve re-proves that the private key under the locator belongs to that public key — with
whichever capability the key has.

```mermaid
flowchart TD
    K(["private key, CKO_PRIVATE_KEY"]) --> PO{"publicOnly?"}
    PO -- "yes: adopt through the public object,<br/>no login (spares PIV PIN retries)" --> TA(["binding = token-asserted<br/>(publicOnly implies it; recorded)"]);
    PO -- no --> B{"tokens.&lt;t&gt;.binding"}
    B -- "unset → pop-sign" --> S{"CKA_SIGN = true declared?"}
    S -- no --> X(["exit 17: declare the capability,<br/>choose a matching pop-*, or opt out"])
    S -- yes --> PS(["token signs the fresh challenge:<br/>ECDSA-SHA* / CKM_EDDSA / CKM_SHA256_RSA_PKCS;<br/>host verifies against the SPKI"])
    B -- pop-ecdh --> D{"CKK_EC (not Edwards)<br/>and CKA_DERIVE = true?"}
    D -- no --> X
    D -- yes --> PE(["host: ephemeral key, MAC of the challenge<br/>under the ECDH secret<br/>token: CKM_ECDH1_DERIVE into a non-extractable<br/>session key, CKM_SHA256_HMAC; MACs compared"])
    B -- pop-decrypt --> E{"CKK_RSA<br/>and CKA_DECRYPT = true?"}
    E -- no --> X
    E -- yes --> PD(["host: RSA-OAEP (SHA-1) challenge<br/>token: CKM_RSA_PKCS_OAEP;<br/>plaintext compared constant-time"])
    B -- token-asserted --> TA2(["no proof: the token's word only.<br/>A later drop from any pop-* to this is refused (14)"])
```

All `pop-*` share the top binding rank: each proves possession of the same key. A key carrying
`CKA_ALWAYS_AUTHENTICATE` is refused at run time (16) — a proof would spend a PIN entry per run.

## 4. Identity: one object, several schemes

The lock may hold several ids per object — one per *scheme*, each an SRI digest. A scheme is
frozen forever (§10 of DESIGN): a changed computation gets a new name, and `DEPRECATED_SCHEMES`
(empty today) is the deprecation register.

```mermaid
flowchart LR
    PK["private / public keys"] --> R["rfc7093m4<br/>SHA-256 of the canonical SPKI<br/>host-verified"]
    C["certificates<br/>(CKC_X_509)"] --> CH["certhash<br/>SHA-256 of the DER"]
    C --> R
    D["data objects"] --> VH["valuehash<br/>SHA-256 of CKA_VALUE<br/>(= Nix flat FOD hash)"]
    G["generic secret<br/>CKK_SHA*_HMAC"] --> COM["commitment<br/>HMAC over the label,<br/>the key type's hash"]
    A["AES"] --> CM["cmac"]
    CM -- weaker --> K1["kcv-ecb"]
    K1 -- weaker --> K2["kcv-ecb-dec"]
    K2 -- weaker --> KW["kw"]
    style CM fill:#dfe
    style KW fill:#fdd
```

Only the declared usage bits decide which commitment schemes run (CKA_SIGN → cmac,
CKA_ENCRYPT → kcv-ecb, …); the first computed is the primary scheme, and the lock stores only
SHA-256 of the token's output, never a MAC or ciphertext under the key.

## 5. Usage: the Nix loop

```mermaid
flowchart LR
    KT["keys.toml"] --> MK["lib.mkKeys { cakeys }"]
    KL["keys.lock"] --> MK
    MK -->|"keys.&lt;object&gt; { token, spec, scheme }<br/>→ uri · rsf · id · check"| DRV["consumer derivation"]
    DRV -->|"requiredSystemFeatures =<br/>[ token-&lt;name&gt; ]"| HOOK["Nix pre-build hook<br/>(nix/sandbox-hook.sh)"]
    HOOK -->|"grants the token's device/socket<br/>only to builds asking for its feature"| SB["build sandbox"]
    SB --> CHK["cakeys check &lt;obj&gt;.id.&lt;scheme&gt;"]
    CHK -->|"first use: autoCreate, then fail<br/>with got: sha256-…"| OOB["record out of band:<br/>cakeys realise --update-lock"]
    OOB -.-> KL
    CHK -->|"every later build: the CA-ID<br/>is recomputed and compared"| URI["pkcs11: URI on stdout"]
```

The token a real build may reach is a p11-kit forwarding socket or a real TPM (`/dev/tpmrm0`) —
never a token database, whose files would allow offline PIN guessing.
