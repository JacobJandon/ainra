<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M28 — the fourth rung: instance credentials

**R1 from [`SETTLERS.md`](SETTLERS.md), taken as a milestone rather than an amendment.** ADR-017 names a five-rung
validity ladder. Four rungs are built. The fourth — the credential a *running copy* carries — is declared and
unbuilt, and this milestone builds it.

---

## Task 0 · The before state, with evidence

### The ladder as ADR-017 states it

| Rung | Lifetime | Built? |
|---|---|---|
| lineage + AINRA Number | ∞ | ✅ |
| passport | 366 d | ✅ [`consts.rs:16`](../crates/ainra-core/src/consts.rs) |
| delegate certificates | ≤ 92 d | ✅ [`consts.rs:23`](../crates/ainra-core/src/consts.rs), enforced at build *and* verify |
| **instance credentials** | **minutes–hours** | ❌ **declared only** |
| status freshness | seconds (F1/F2/F3) | ✅ |

The fourth rung's constant exists and is used by nothing:

```rust
// crates/ainra-core/src/consts.rs:26-29
/// Default instance-credential lifetime — **1 hour** (ADR-017: minutes–hours). RESERVED: the instance-credential
/// layer (SPIFFE-style short-lived running-copy creds under the passport) is future work; the constant pins the
/// ADR-017 ceiling here so the ladder has one home and later machinery cannot invent its own number.
pub const INSTANCE_CRED_DEFAULT_SECS: u64 = 60 * 60;
```

`grep -rn INSTANCE_CRED` finds it in exactly two places: its declaration, and the ladder-ordering test that asserts
it is smaller than the delegate ceiling. **Nothing reads it.**

### Where a running copy gets its key today

It is handed the lineage's own long-lived private key, written to disk in the clear:

```js
// apps/cli-node/bin/ainra.js:220
save(P('passports', serial + '.agent.key'), agentKey.priv);

// apps/cli-node/bin/ainra.js:85 — no mode argument, so the file lands at the umask default
const save = (p, o) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, …); };
```

Measured, not inferred — a real `init` → `accredit` → `issue` on a clean `AINRA_HOME`:

```
  AP-1740-4F.agent.key           mode=644
  AP-1740-4F.json                mode=644
  keys in file: ed25519, mldsa65
  ed25519 starts: -----BEGIN PRIVATE KEY----- MC4C
  mldsa65 length: 5376 chars (base64 secret)
  validity: {"issued":"2026-08-18T…","expires":"2027-08-19T…"}   ← 366 days
```

So the running copy holds **the full hybrid secret for the whole lineage**, at **mode 644** (readable by every user
on the host), for **366 days**.

### What the verifier checks about the presenter — nothing

The nine steps ([`verify.rs:118-183`](../crates/ainra-core/src/verify.rs)) are: schema · registrar accredited ·
validity window · issuer signature · scope ceiling · delegation chain · status freshness + revocation · mandate
subtree · logged-before-valid. **None of them asks the presenter to prove it holds anything.**

The passport carries a confirmation claim, but it is opaque and unread:

```rust
// crates/ainra-core/src/passport.rs:137
/// Holder-binding confirmation (opaque; e.g. a JWK thumbprint). Free-form map, denylist-scanned.
pub cnf: Value,
```

`grep -n "cnf\|jkt" crates/ainra-core/src/verify.rs` returns only test fixtures — the field is scanned for PII and
never otherwise consulted. The gate confirms the shape: [`middleware/src/index.ts:32-57`](../packages/middleware/src/index.ts)
takes a bundle out of a header, verifies it, and allows the request. There is no caller signature, nonce, or
audience anywhere in that path.

**A presentation bundle is therefore a bearer token.** Whoever holds the bytes is, to every verifier, the agent.

The project already says so, and this milestone does not get to pretend it is a discovery:

```
docs/STATUS.md:307-308
- Holder keys are real and thumbprint-bound, but proof-of-possession (KB-JWT / RFC 9421 presentation) is not yet
  exercised by the verifier — the schema carries real material for it; the possession check is later work.
```

### The before-sentence

> **An attacker who reads one running container walks away with the lineage's long-lived hybrid private key — world-readable at mode 644 — and with a presentation that every verifier accepts as a bearer token, carrying the passport's full capabilities for the remainder of its 366-day window, anywhere in the world, and the only remedy is revoking the passport itself, which kills every other honest copy along with the stolen one.**

That sentence is the milestone's target. It is quoted back at the end as the after.

### What this milestone must NOT do

**Shortening the passport is forbidden**, and the reason is not squeamishness. ADR-017 chose a long credential
*because* revocation fails closed in under 60 seconds — the deliberate inverse of Web PKI's shrinking-certificate
answer to soft-fail revocation. Shortening it to reduce the blast radius of a stolen key would silently reverse a
decision whose reasoning still holds, and would trade a sound property away to paper over a missing layer. The
blast radius is the *instance* rung's job. Build the rung.

---

## Task 1 · ADR-019 — the instance rung, decided in the open

Recorded as **D-047** in [`DECISIONS.md`](DECISIONS.md). The MTS is frozen; this milestone does not open it, so
ADR-019 lives here and in the decision record, exactly as ADR-017 was implemented through D-027.

### The shape

```
InstanceCredential {
  sub            the passport's subject — which lineage this copy runs
  iid            opaque instance id (non-PII by construction: random, never a hostname)
  ikey           the INSTANCE's own hybrid public key (Ed25519 + ML-DSA-65)
  nbf, exp       minutes–hours, exp − nbf ≤ INSTANCE_CRED_DEFAULT_SECS
  capabilities   ⊆ the passport's capabilities
  aud            the audience this credential may be presented to
  passport_leaf  base64url(prelog_leaf(passport claims)) — binds to the ALREADY-LOGGED passport
  sig            HYBRID signature by the PASSPORT's control key over the canonical bytes
}
```

and, at presentation time, a proof the presenter holds `ikey`:

```
InstancePop { aud, nonce, ts, sig }    sig = hybrid signature by the INSTANCE key
```

### 1 · Who signs — the passport's control key

**Decided:** the passport's own control key (`keys[0]`), held by the operator's issuing side, **never shipped into
the container**. The container receives only its instance private key and a credential that expires within the hour.

*Rejected — the registrar signs.* It puts the registrar in the hot path of every container start: a network round
trip per instance, an offline agent made impossible, and the registrar learning instance-level topology it has no
business knowing. That last point is charter-adjacent: the root and its registrars are not told who is running what.

*Rejected — a separate delegated instance-signing key.* One more long-lived secret to steal, sited on the same
machine that mints, buying nothing at this depth. The ladder already has a delegation rung (≤92 d) for parties, not
for processes.

*Threat answered:* the container no longer holds anything that outlives it. The compromise story becomes "an
attacker gets this instance's key and a credential measured in minutes", instead of "the lineage's key for a year".

### 2 · Log or no log — no per-instance log entry, bound to the logged leaf instead

**Decided:** instance credentials are **not logged**. Each carries `passport_leaf`, the `prelog_leaf` of the
passport it runs under, and verification requires that leaf to equal the presented passport's — whose inclusion is
proven by step 9 as it always was.

*Rejected — log every instance credential.* A container start becomes a log append. At any real scale that is
millions of entries a day whose only content is "a process started", it puts the transparency log in the hot path
of every deploy, and it drowns the entries that matter — the issuances — in operational noise.

*The tradeoff, stated plainly.* **What an attacker gains from the absence of a per-instance entry:** a stolen
*control* key can mint instance credentials that leave no public trace, so nobody can enumerate the copies that ever
existed. **Why that is bounded:** control-key compromise is already the catastrophic case — that key can mint a
credential for anything the lineage may do, logged or not — and the bound that matters is the same one that bounds
everything else here: revoking the passport kills every instance under it within the freshness window, whether or
not each instance was ever written down. Logged-before-valid stays meaningful at the layer where it decides
something: **you cannot mint an instance credential for a passport that was never logged**, because the leaf will
not match.

### 3 · Lifetime and the clock — 1 hour default, exact window, no skew

**Decided:** `INSTANCE_CRED_DEFAULT_SECS` (1 h) is both the default and the enforced ceiling; `exp − nbf` greater
than it is refused at verify, not merely at issuance. The window comparison is exact — `nbf ≤ now < exp` — with **no
skew tolerance**, matching the passport rung.

*Rejected — apply ADR-016's ±30 s.* ADR-016 scopes its tolerance to freshness-layer signed timestamps (heads and
checkpoints), never to a validity window, and `consts.rs:8-12` says so. A skewed validity window is a grace period
wearing a different hat, and ADR-017 forbids grace periods anywhere: expiry is expiry.

*At the boundary:* `now == exp` → **expired**; `now == exp − 1` → valid; `now == nbf − 1` → **not yet valid**.
Vectors pin all three.

### 4 · Scope — narrowing only, one rung down

**Decided:** `ic.capabilities ⊆ passport.capabilities ⊆ passport.scope_ceiling`. An instance credential may only
ever narrow. Widening is refused with its own named reason, not folded into `ceiling_exceeded`.

*Rejected — let an instance hold the passport's full capability set by default.* Convenient, and it throws away the
main reason to have the rung: the blast radius of a compromised container should be smaller than the lineage's
authority, not equal to it. The ∩ rule is the same one the delegation chain already enforces at `verify.rs:159`.

### 5 · Suite — hybrid, both-or-invalid, no exception

**Decided:** the same rule as every other signature in the system. Both Ed25519 and ML-DSA-65 verify, or the
credential is invalid.

*Rejected — Ed25519 only, for speed.* "Faster" is not an argument on the verify path without a measurement, and the
measurement does not support it: a full nine-step verify including an ML-DSA-65 signature and an SLH-DSA checkpoint
costs **402 µs** (`docs/BENCHMARKS.md`, regenerated this milestone). An instance credential adds one hybrid
signature plus one PoP signature to that. A post-quantum hole opened at the rung closest to the workload, to save
tens of microseconds, would be the cheapest possible way to lose the property the rest of the system pays for.

### 6 · Binding and anti-replay — audience + proof-of-possession, and what it does not stop

**Decided:** two mechanisms, and both are required.

- **Audience binding.** The credential names the `aud` it may be presented to; a verifier is configured with its own
  audience and refuses anything addressed elsewhere.
- **Proof-of-possession.** The presenter signs `(aud, nonce, ts)` with the *instance* private key. The verifier
  checks that signature against `ikey` from the credential. This is what converts the presentation from a **bearer**
  token into a **holder-bound** one — the single largest change in this milestone.

*Rejected — nonce replay cache in core.* `ainra-core` is N7: no I/O, no clock, no state. A replay cache is state,
and putting it in the pure verifier would break the property that makes the verifier trivially auditable and
embeddable. The nonce is carried and bound; **enforcing single-use is the caller's business**, and the SDK helper
says so at the call site rather than pretending otherwise.

**Name what each does not stop, plainly:**

| Mechanism | Stops | Does **not** stop |
|---|---|---|
| audience binding | presenting a stolen credential to a *different* service | replay against the same service |
| proof-of-possession | replaying an exfiltrated *bundle* from another machine | an attacker with live access to the container, who has the instance key |
| `ts` freshness window | an old PoP replayed much later | replay inside the window |
| short lifetime | everything, eventually — within the hour | anything within that hour |

The honest summary: this rung does not make a compromised container harmless. It makes the compromise **bounded in
time, bounded in scope, and killable from outside** — which is exactly the three things it was not before.

### 7 · Revocation — expiry is the mechanism, and passport revocation must kill every instance

**Decided:** instance credentials are not individually revocable; they are short enough that expiry *is* the
revocation mechanism. But revoking the **passport** must kill every live instance under it, through the existing
fail-closed status check — and that is a claim to be **proven, not asserted**. The `instance-passport-revoked-*`
vector family exists for exactly this: the instance credential is well-formed, unexpired, correctly scoped, and its
PoP verifies — and the verdict is `revoked`, because the passport underneath it is.

*Rejected — a per-instance revocation list.* It would need its own status infrastructure, its own freshness class,
and its own propagation SLO, to revoke credentials that expire in an hour by themselves.

### 8 · Failure reasons — four new named reasons, none of them reused

**Decided:** every new way this can fail gets its own frozen string, because an integrator debugging a rejected
instance credential must not be handed a reason that describes a different problem.

| Reason | Fires when |
|---|---|
| `instance_expired` | the instance window is closed (or opens later), or `exp − nbf` exceeds the ceiling |
| `instance_scope_exceeds` | `ic.capabilities ⊄ passport.capabilities` |
| `instance_sig_invalid` | the credential's hybrid signature does not verify under the passport's key, or the credential is not bound to this passport's leaf |
| `instance_pop_invalid` | the proof-of-possession fails: wrong audience, stale `ts`, or a signature that does not verify under `ikey` |

*Rejected — reuse `expired`, `ceiling_exceeded`, `sig_invalid`.* Each would send a debugging integrator to the wrong
layer: `expired` reads as "your passport ran out" when the passport is fine and the container simply needs to renew;
`sig_invalid` reads as "the registrar's signature is broken". A reason string is a diagnostic contract, and this is
the same lesson `reasons-check` was built for one commit ago.


---

## Task 3 · What a running copy carries — in plain language

**Before this milestone the answer was: everything.** The container held the lineage's own private key, and the
bundle it presented was a bearer token. Now it holds a credential that expires in minutes, is narrower than the
passport, is bound to a key only that copy has, and dies the moment the passport is revoked.

The whole lifecycle, run on a clean `AINRA_HOME` — captured output, not an illustration:

```
$ ainra issue ainra:reg-eu-1:acme:billing@1.0.0
✓ passport issued · ainra:reg-eu-1:acme:billing@1.0.0
  serial AP-5F80-9A · tier L3 · class A1 · key FP 687A:DD3A:4587:89ED

$ ainra instance issue ainra:reg-eu-1:acme:billing@1.0.0 --aud https://api.example --caps read:invoices --ttl 900
✓ instance credential issued · i-9cda138a
  under ainra:reg-eu-1:acme:billing@1.0.0 (AP-5F80-9A) · expires in 900s · capabilities read:invoices
  audience https://api.example
  container gets: i-9cda138a.instance.json + i-9cda138a.instance.key (0600). The passport key stays here.

$ ls -l $AINRA_HOME/passports/     # what the container gets, and what it does not
-rw-------  AP-5F80-9A.agent.key
-rw-r--r--  AP-5F80-9A.json
-rw-------  i-9cda138a.instance.json
-rw-------  i-9cda138a.instance.key

$ ainra instance verify i-9cda138a --aud https://api.example
✓ VALID · i-9cda138a under ainra:reg-eu-1:acme:billing@1.0.0
  900s of life left · capabilities read:invoices · audience https://api.example
  the passport underneath verified first: unrevoked and in-window — revoke it and this dies with it
  note: this passport format carries no capabilities array, so the ∩ rule is not checked here

$ ainra instance verify i-9cda138a --aud https://elsewhere.example    # a stolen copy, replayed
✗ INVALID · i-9cda138a
  instance_pop_invalid (addressed to https://api.example, not https://elsewhere.example)

$ ainra revoke ainra:reg-eu-1:acme:billing@1.0.0 --reason compromise
✓ revoked · ainra:reg-eu-1:acme:billing@1.0.0 · reason: compromise · log #000003
  every verifier reading this status list now rejects it — that is the whole switch.

$ ainra instance verify i-9cda138a --aud https://api.example    # the same copy, unchanged
✗ INVALID · i-9cda138a
  revoked (the PASSPORT under this copy is revoked — every live instance dies with it)
```

Four things to read out of that transcript:

1. **The passport key never leaves.** `AP-....agent.key` stays where the mint happened. The container is handed
   `i-....instance.json` + `i-....instance.key` and nothing else — and all of it is `-rw-------`, which is new:
   every secret this CLI wrote was `-rw-r--r--` until this milestone, world-readable on a shared host.
2. **900 seconds, not 366 days.** The ceiling is one hour and it is enforced at *verify*, so a cooperative minter
   is not the only thing standing between you and a year-long "instance" credential.
3. **A stolen copy replayed at another service is refused** — `instance_pop_invalid`, naming both audiences.
4. **Revoking the passport kills the copy**, and reports `revoked` rather than an instance reason: the lineage
   failed, not the container, and the reason has to send whoever is debugging to the right layer.

### The one honest limitation, printed where it is easiest to miss

The line *"this passport format carries no capabilities array, so the ∩ rule is not checked here"* is printed by
the CLI **on success**, on purpose. The reference CLI's fmt-2 passport carries a tier and an authority class, not
a capability list, so narrowing cannot be verified in that path. The core, both SDKs and the browser verifier all
enforce it, and `instance-scope-exceeds-*` pins it across the corpus — but a command that silently skipped a check
while printing a tick would be worse than one that names the check it did not run.

### The after-sentence

> **An attacker who reads one running container walks away with that copy's own key and a credential scoped below
> the passport, valid for the minutes left on its clock, refused by every service it was not addressed to, and dead
> the moment the passport is revoked — while the lineage's key was never in the container to steal.**

Set against the before-sentence at the top of this file, three things changed and one deliberately did not: the
blast radius is now **bounded in time** (≤1 h, enforced at verify), **bounded in scope** (⊆ the passport's
capabilities), and **bound to a holder** (audience + proof-of-possession) — and the passport is still 366 days,
because ADR-017's reasoning for that never depended on the container being trustworthy.

It still does not make a compromised container harmless. An attacker with live access holds the instance key and
acts as the agent until the credential expires. That is stated in the module doc, in the ADR, and here.
