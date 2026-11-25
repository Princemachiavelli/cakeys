// -*- mode: Bluespec; -*-
/// The lock rules (crates/core/src/reconcile.rs: `reconcile`, `compare`, `record`; docs/LOCK.md)
/// over an abstract keys.lock: what one realisation run does to the lock, and its verdict.
///
/// crates/core/tests/lock_mbt.rs replays this model's traces against the Rust (quint-connect):
/// each `realise` step's picks become a `Target` and a `Resolved`, the real `reconcile` runs, and
/// the lock it leaves (projected onto `Lock` below) and its verdict must be this model's.
///
/// The keys.toml is fixed and small, the one lock_mbt.rs builds: tokens t1 and t2; the EC
/// private keys k, whose curve one keys.toml edit changes, and k2; the AES key aes. Specs s
/// (k on t1 and t2), s2 (k2 on t1) and a (aes on t1 and t2). Material is a number, not a
/// hash: two IDs are equal exactly when their scheme and material are.
///
/// Left out, so neither modelled nor checked: imports (`facts.origin`, provenance);
/// observations and `observed` (warnings only); notes; pairs and `publicKey` (no certificate,
/// public key or transport key in this keys.toml); locators and `publicOnly` (fixed per spec,
/// so `spec_unchanged` sees only the spec digest); deprecated schemes (there are none);
/// commitment labels other than the default; attestation on a secret key; a spec pointed at
/// another object (`compare` judges no downgrade across objects; a unit test in reconcile.rs
/// covers it). A private key always
/// arrives with a binding (the planner's precondition, and a load rule of the lock).
module lock {
  type Write = Compare | Record
  type Mode = Direct | Commitment | WrapRebind
  type Binding = Unbound | PopSign | PopEcdh | TokenAsserted
  type Flag = Unset | Yes | No
  type Attestation = Unattested | Attested({ anchor: int, id: int })
  /// `Ok(changed)`, or the exit code of the error.
  type Verdict = Ok(bool) | Exit(int)

  type Immutables = { local: Flag, neverExtractable: Flag, alwaysSensitive: Flag }
  /// The policy vector: `CKA_SIGN` and `CKA_DECRYPT`, `Unset` when the token does not report it.
  type Policy = { sign: Flag, decrypt: Flag }

  /// What the token reports for one realisation (`Resolved`), and how the run writes.
  type Input = {
    spec: str,
    token: str,
    write: Write,
    // keys.toml's curve for k: another one is another object type.
    curve: str,
    material: int,
    schemes: Set[str],
    mode: Mode,
    binding: Binding,
    attestation: Attestation,
    policy: Policy,
    immutables: Immutables,
    specDigest: int,
  }

  type LockObject = { typ: str, ids: str -> int, labelled: bool }
  type Realisation = {
    object: str,
    mode: Mode,
    binding: Binding,
    schemes: Set[str],
    attestation: Attestation,
    policy: Policy,
    immutables: Immutables,
    specDigest: int,
  }
  type Lock = { objects: str -> LockObject, realisations: str -> (str -> Realisation) }

  // keys.toml

  pure val SPECS: str -> { object: str, tokens: Set[str] } = Map(
    "s" -> { object: "k", tokens: Set("t1", "t2") },
    "s2" -> { object: "k2", tokens: Set("t1") },
    "a" -> { object: "aes", tokens: Set("t1", "t2") },
  )
  pure val TARGETS: Set[(str, str)] = SPECS.keys().map(s => SPECS.get(s).tokens.map(t => (s, t))).flatten()
  pure val CURVES = Set("secp256r1", "secp384r1")
  pure val EC_SCHEMES = Set("rfc7093m4")
  pure val AES_SCHEMES = Set("cmac", "kcv-ecb", "kcv-ecb-dec", "kw")
  pure val MATERIALS = Set(1, 2)
  pure val FLAGS = Set(Unset, Yes, No)

  pure def objectOf(spec: str): str = SPECS.get(spec).object
  pure def isSecret(object: str): bool = object == "aes"
  pure def typeOf(object: str, curve: str): str =
    if (object == "k") curve else if (object == "k2") "secp256r1" else "aes"

  // What a token can report for an object of each kind.
  pure def schemesFor(object: str): Set[Set[str]] =
    if (isSecret(object)) AES_SCHEMES.powerset().exclude(Set(Set())) else Set(EC_SCHEMES)
  pure def modesFor(object: str): Set[Mode] =
    if (isSecret(object)) Set(Commitment, WrapRebind) else Set(Direct)
  pure def bindingsFor(object: str): Set[Binding] =
    if (isSecret(object)) Set(Unbound) else Set(PopSign, PopEcdh, TokenAsserted)
  pure def attestationsFor(object: str): Set[Attestation] =
    if (isSecret(object)) Set(Unattested)
    else Set(Unattested).union(tuples(Set(1, 2), Set(1, 2)).map(((a, i)) => Attested({ anchor: a, id: i })))
  pure val POLICIES: Set[Policy] = tuples(FLAGS, FLAGS).map(((s, d)) => { sign: s, decrypt: d })
  pure val IMMUTABLES: Set[Immutables] =
    tuples(FLAGS, FLAGS, FLAGS).map(((l, n, a)) => { local: l, neverExtractable: n, alwaysSensitive: a })

  // Strength, strongest 0 (`Mode::rank`, `Binding::rank`).
  pure def modeRank(m: Mode): int = match m {
    | Direct => 0
    | Commitment => 1
    | WrapRebind => 2
  }
  pure def bindingRank(b: Binding): int = match b {
    | TokenAsserted => 1
    | _ => 0
  }

  // The lock

  pure val EMPTY: Lock = { objects: Map(), realisations: Map() }

  pure def hasRealisation(l: Lock, spec: str, token: str): bool =
    l.realisations.keys().contains(spec) and l.realisations.get(spec).keys().contains(token)

  pure def lockedIds(l: Lock, object: str): str -> int =
    if (l.objects.keys().contains(object)) l.objects.get(object).ids else Map()

  /// The verdict of a check: 0 to go on, else the exit code and the rule that decided it.
  type Check = { code: int, rule: str }
  pure val PASS: Check = { code: 0, rule: "" }
  pure def refuse(code: int, rule: str): Check = { code: code, rule: rule }
  pure def andThen(c: Check, after: Check): Check = if (c.code != 0) c else after
  pure def refuseIf(cond: bool, code: int, rule: str): Check = if (cond) refuse(code, rule) else PASS

  /// `Immutables::weakened_since`: a flag recorded true that is not true now.
  pure def weakened(was: Immutables, now: Immutables): bool = or {
    was.local == Yes and now.local != Yes,
    was.neverExtractable == Yes and now.neverExtractable != Yes,
    was.alwaysSensitive == Yes and now.alwaysSensitive != Yes,
  }

  /// `no_downgrade`: what the realisation proved when locked it must still prove.
  pure def noDowngrade(p: Realisation, i: Input): Check =
    if (modeRank(i.mode) > modeRank(p.mode)) refuse(14, "mode")
    else if (p.binding != Unbound and i.binding != Unbound and bindingRank(i.binding) > bindingRank(p.binding))
      refuse(14, "binding")
    else {
      val attestation = match p.attestation {
        | Unattested => PASS
        | Attested(was) => match i.attestation {
          | Unattested => refuse(14, "attestation-lost")
          | Attested(now) =>
            if (was.anchor != now.anchor) refuse(14, "anchor")
            else if (was.id != now.id) refuse(10, "attestation-id")
            else PASS
        }
      }
      attestation
        .andThen(refuseIf(p.schemes.exists(s => not(i.schemes.contains(s))), 14, "schemes-lost"))
        .andThen(refuseIf(weakened(p.immutables, i.immutables), 14, "replaced"))
    }

  /// `object_diff`: a policy attribute the lock recorded that reads otherwise (or not at all),
  /// or other immutables.
  pure def objectChanged(p: Realisation, i: Input): bool = or {
    p.policy.sign != Unset and i.policy.sign != p.policy.sign,
    p.policy.decrypt != Unset and i.policy.decrypt != p.policy.decrypt,
    p.immutables != i.immutables,
  }

  /// The rules against the realisation the lock records for this spec on this token.
  pure def againstRealisation(p: Realisation, i: Input): Check = {
    val update = i.write == Record
    refuseIf(not(update) and p.specDigest != i.specDigest, 14, "spec")
      .andThen(noDowngrade(p, i))
      .andThen(refuseIf(not(update) and objectChanged(p, i), 14, "object"))
  }

  /// `compare_ids`: material links only through a shared scheme, never overrides a locked ID,
  /// and a clean compare needs the realisation recorded.
  pure def compareIds(l: Lock, i: Input): Check = {
    val update = i.write == Record
    val locked = lockedIds(l, objectOf(i.spec))
    val shared = i.schemes.filter(s => locked.keys().contains(s))
    if (locked.keys() != Set() and shared == Set()) refuse(14, "unlinked")
    else if (shared.exists(s => locked.get(s) != i.material)) refuse(10, "mismatch")
    else if (not(update) and shared == Set()) refuse(18, "first-use")
    else if (not(update) and not(hasRealisation(l, i.spec, i.token))) refuse(14, "unrealised")
    else PASS
  }

  /// `compare`, in the order that decides the exit code.
  pure def compare(l: Lock, i: Input): Check = {
    val object = objectOf(i.spec)
    val typeChanged = l.objects.keys().contains(object) and l.objects.get(object).typ != typeOf(object, i.curve)
    refuseIf(typeChanged, 14, "type")
      .andThen(if (hasRealisation(l, i.spec, i.token)) againstRealisation(l.realisations.get(i.spec).get(i.token), i) else PASS)
      .andThen(compareIds(l, i))
  }

  /// `record`'s refusal: the same material under a second name of the same class.
  pure def secondName(l: Lock, i: Input): Check = {
    val object = objectOf(i.spec)
    val other = l.objects.keys().exists(o => and {
      o != object,
      isSecret(o) == isSecret(object),
      i.schemes.exists(s => l.objects.get(o).ids.keys().contains(s) and l.objects.get(o).ids.get(s) == i.material),
    })
    if (other) refuse(14, "second-name") else PASS
  }

  /// `record`: fill the object's gaps (type, label, IDs; never an ID it has) and replace this
  /// realisation.
  pure def recorded(l: Lock, i: Input): Lock = {
    val object = objectOf(i.spec)
    val was =
      if (l.objects.keys().contains(object)) l.objects.get(object)
      else { typ: typeOf(object, i.curve), ids: Map(), labelled: false }
    val entry = {
      typ: was.typ,
      ids: was.ids.keys().union(i.schemes).mapBy(s => if (was.ids.keys().contains(s)) was.ids.get(s) else i.material),
      labelled: was.labelled or isSecret(object),
    }
    val realisation = {
      object: object,
      mode: i.mode,
      binding: i.binding,
      schemes: i.schemes,
      attestation: i.attestation,
      policy: i.policy,
      immutables: i.immutables,
      specDigest: i.specDigest,
    }
    val byToken = if (l.realisations.keys().contains(i.spec)) l.realisations.get(i.spec) else Map()
    {
      objects: l.objects.put(object, entry),
      realisations: l.realisations.put(i.spec, byToken.put(i.token, realisation)),
    }
  }

  /// `reconcile`: the lock after the run, its verdict, and the rule that decided it.
  pure def reconcile(l: Lock, i: Input): (Lock, Verdict, str) = {
    val compared = compare(l, i)
    if (compared.code != 0) (l, Exit(compared.code), compared.rule)
    else if (i.write == Compare) (l, Ok(false), "compared")
    else {
      val refused = secondName(l, i)
      if (refused.code != 0) (l, Exit(refused.code), refused.rule)
      else {
        val written = recorded(l, i)
        (written, Ok(written != l), if (written != l) "recorded" else "unchanged")
      }
    }
  }

  // The state

  var lock: Lock
  var verdict: Verdict
  // Ghosts, for the invariants and the generator; lock_mbt.rs does not compare them.
  var before: Lock
  var input: Input
  var rule: str
  /// What each target last reported: most runs drift one field from it, as a token does.
  var seen: (str, str) -> Input

  pure val NO_INPUT: Input = {
    spec: "s",
    token: "t1",
    write: Compare,
    curve: "secp256r1",
    material: 1,
    schemes: EC_SCHEMES,
    mode: Direct,
    binding: PopSign,
    attestation: Unattested,
    policy: { sign: Unset, decrypt: Unset },
    immutables: { local: Unset, neverExtractable: Unset, alwaysSensitive: Unset },
    specDigest: 1,
  }

  /// Which field of the last report may change: one, all, or none.
  pure val CHANGES = Set(
    "all", "none", "curve", "material", "schemes", "mode", "binding", "attestation", "policy",
    "immutables", "specDigest",
  )

  action init = all {
    lock' = EMPTY,
    verdict' = Ok(false),
    before' = EMPTY,
    input' = NO_INPUT,
    rule' = "",
    seen' = Map(),
  }

  /// One cakeys run on one target: `lock` (Record) or `check` (Compare).
  action realise = {
    nondet target = TARGETS.oneOf()
    nondet change = CHANGES.oneOf()
    val object = objectOf(target._1)
    val known = seen.keys().contains(target)
    val last = if (known) seen.get(target) else NO_INPUT
    def free(name: str): bool = not(known) or change == "all" or change == name
    nondet write = Set(Compare, Record).oneOf()
    nondet curve = (if (free("curve")) CURVES else Set(last.curve)).oneOf()
    nondet material = (if (free("material")) MATERIALS else Set(last.material)).oneOf()
    nondet schemes = (if (free("schemes")) schemesFor(object) else Set(last.schemes)).oneOf()
    nondet mode = (if (free("mode")) modesFor(object) else Set(last.mode)).oneOf()
    nondet binding = (if (free("binding")) bindingsFor(object) else Set(last.binding)).oneOf()
    nondet attestation = (if (free("attestation")) attestationsFor(object) else Set(last.attestation)).oneOf()
    nondet policy = (if (free("policy")) POLICIES else Set(last.policy)).oneOf()
    nondet immutables = (if (free("immutables")) IMMUTABLES else Set(last.immutables)).oneOf()
    nondet digest = (if (free("specDigest")) Set(1, 2) else Set(last.specDigest)).oneOf()
    val i = {
      spec: target._1,
      token: target._2,
      write: write,
      curve: curve,
      material: material,
      schemes: schemes,
      mode: mode,
      binding: binding,
      attestation: attestation,
      policy: policy,
      immutables: immutables,
      specDigest: digest,
    }
    val result = reconcile(lock, i)
    all {
      lock' = result._1,
      verdict' = result._2,
      before' = lock,
      input' = i,
      rule' = result._3,
      seen' = seen.put(target, i),
    }
  }

  // `any`, so a trace names the action taken: `realise`, not `step`.
  action step = any { realise }

  // Invariants: what the rules are for (docs/LOCK.md, docs/DESIGN.md).

  pure def isOk(v: Verdict): bool = match v {
    | Ok(_) => true
    | Exit(_) => false
  }

  /// A failed run, and any compare, leaves the lock as it was.
  val onlyAWriteWrites = (not(isOk(verdict)) or input.write == Compare) implies lock == before

  /// No run overwrites a locked ID or type, or drops an object or a label.
  val neverOverwritten = before.objects.keys().forall(o => and {
    lock.objects.keys().contains(o),
    lock.objects.get(o).typ == before.objects.get(o).typ,
    before.objects.get(o).labelled implies lock.objects.get(o).labelled,
    before.objects.get(o).ids.keys().forall(s =>
      lock.objects.get(o).ids.keys().contains(s) and lock.objects.get(o).ids.get(s) == before.objects.get(o).ids.get(s)
    ),
  })

  /// An object's IDs are all of one material: material links to it only through a shared scheme.
  val oneMaterialPerObject = lock.objects.keys().forall(o => {
    val ids = lock.objects.get(o).ids
    ids.keys().forall(s => ids.keys().forall(t => ids.get(s) == ids.get(t)))
  })

  /// One object per material: no two objects of a class share a scheme's ID.
  val oneObjectPerMaterial = lock.objects.keys().forall(o => lock.objects.keys().forall(p => or {
    o == p,
    isSecret(o) != isSecret(p),
    {
      val a = lock.objects.get(o).ids
      val b = lock.objects.get(p).ids
      a.keys().forall(s => not(b.keys().contains(s)) or a.get(s) != b.get(s))
    },
  }))

  /// Every realisation's schemes are among its object's IDs (a load rule of the lock).
  val realisedSchemesAreLocked = lock.realisations.keys().forall(s => lock.realisations.get(s).keys().forall(t => {
    val r = lock.realisations.get(s).get(t)
    lock.objects.keys().contains(r.object) and r.schemes.subseteq(lock.objects.get(r.object).ids.keys())
  }))

  /// A successful run never lowers what a recorded realisation proved: its mode, binding,
  /// attestation, schemes and immutables.
  val neverDowngraded =
    (isOk(verdict) and hasRealisation(before, input.spec, input.token)) implies {
      val p = before.realisations.get(input.spec).get(input.token)
      val n = lock.realisations.get(input.spec).get(input.token)
      and {
        modeRank(n.mode) <= modeRank(p.mode),
        bindingRank(n.binding) <= bindingRank(p.binding),
        p.attestation == Unattested or n.attestation == p.attestation,
        p.schemes.subseteq(n.schemes),
        not(weakened(p.immutables, n.immutables)),
      }
    }

  /// What a write recorded compares clean, and writing it again changes nothing.
  val recordedComparesClean =
    (input.write == Record and isOk(verdict)) implies and {
      reconcile(lock, { ...input, write: Compare }) == (lock, Ok(false), "compared"),
      reconcile(lock, input) == (lock, Ok(false), "unchanged"),
    }

  val invariants = and {
    onlyAWriteWrites,
    neverOverwritten,
    oneMaterialPerObject,
    oneObjectPerMaterial,
    realisedSchemesAreLocked,
    neverDowngraded,
    recordedComparesClean,
  }

  // Witnesses: each rule that can decide a run, for `quint run --witnesses` to count.

  val decidedByType = rule == "type"
  val decidedBySpec = rule == "spec"
  val decidedByMode = rule == "mode"
  val decidedByBinding = rule == "binding"
  val decidedByAnchor = rule == "anchor"
  val decidedByAttestationId = rule == "attestation-id"
  val decidedByAttestationLost = rule == "attestation-lost"
  val decidedBySchemesLost = rule == "schemes-lost"
  val decidedByReplaced = rule == "replaced"
  val decidedByObject = rule == "object"
  val decidedByUnlinked = rule == "unlinked"
  val decidedByMismatch = rule == "mismatch"
  val decidedByFirstUse = rule == "first-use"
  val decidedByUnrealised = rule == "unrealised"
  val decidedBySecondName = rule == "second-name"
  val decidedByCompared = rule == "compared"
  val decidedByRecorded = rule == "recorded"
  val decidedByUnchanged = rule == "unchanged"
}
