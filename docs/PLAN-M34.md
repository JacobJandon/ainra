<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M34 — the presentation layer becomes real

Everything below the presentation is finished and proven: a credential chains to the root, fails closed on
revocation, and four implementations agree on it over 1153 vectors. The step where that credential is *handed to
somebody* is the one part of the system that is still described rather than built.

This milestone builds it, and in doing so closes a gap the threat model already names.

---

## Task 0 — The probe, before the claim

The Master Technical Specification lists **T-P3, replay of presentation**, with its mitigation stated as
*"RFC 9421 nonce+created, 5-min window, nonce cache"*. Nothing in any implementation does this. A presentation is a
bundle in an ordinary header (`x-ainra-passport`, JSON or base64url), and a header is a bearer token.

Probed against the shipped middleware, using its own fixtures, rather than argued:

```
presentation 1                        → allow=true  valid
presentation 2 (identical replay)     → allow=true  valid
presentation 3 (string form, any caller) → allow=true  valid
verdict event fields: status, reason, name, number, tier, freshness_age_s, instance_iid, instance_exp
```

Three identical presentations, three acceptances, and **not one field binding any of them to a request** — no
method, no authority, no path, no nonce, no timestamp. Anyone who observes a presentation once can present it
anywhere, for as long as the credential lives. The instance rung bounds *how long* that is (≤1 hour, ADR-019); it
does not stop the replay inside the window, and at the passport rung there is no bound at all beyond expiry.

`docs/STATUS.md` states this honestly today. M34 removes the reason to state it.

---

## Task 1 — The contradiction that has to be resolved first

Two normative texts disagree, and the disagreement is load-bearing:

| Source | Says |
|---|---|
| The Standard §5 | "the request signature **names the passport key**, so the credential travels inside ordinary web traffic" |
| ADR-019 / D-047 | the passport's **control key** "mints instance credentials and **never enters the container**" |

A running copy cannot sign with a key it is forbidden to hold. Both cannot be true for the case that matters —
an agent making a request in production.

**The resolution M34 proposes:** the **instance key signs**. The signature's `keyid` names the instance
credential; the instance credential names the passport; the passport chains to the registrar and the root. The
verifier walks that chain as it already does. The passport key signs only where a holder legitimately has it —
issuance, operator tooling, and the mint itself — never in a container.

This preserves the whole point of ADR-019 (a stolen container holds a credential that is bounded, narrow and
killable) and delivers what the passport rung lacks: a presentation that cannot be replayed by whoever copied it.

The Standard is **frozen** and classified **Normative**, so this is an amendment and takes the documented path:
an ADR, a `D-0xx` record, and the era's approval (`GOVERNANCE-AMENDMENT.md`). The same sentence carries a second
drift worth correcting in the same pass: it describes instance credentials as "bound to the connection (mTLS)",
where ADR-019 chose audience binding plus proof-of-possession, which is what shipped.

---

## Task 2 — The profile, stated exactly

An RFC 9421 signature is only as good as what it covers. To be written as a decision record before code:

- **Covered components:** `@method`, `@authority`, `@path`, the presentation header, and `content-digest` when a
  body exists. Omitting any of these leaves a signature that survives being moved to another host or verb.
- **Parameters:** `created`, `nonce`, `keyid`, `alg`. A window (the spec says five minutes) and a **caller-side
  nonce cache**, because `ainra-core` is N7 — it holds no state, so single-use is enforced by the caller and the
  documentation must say so plainly, exactly as ADR-019 already says it for the instance PoP nonce.
- **Hybrid, or not at all** — the same rule as every other signing surface (D-047: no speed exception at the rung
  closest to the workload).
- **Failure is named.** New refusal reasons enter the frozen list, which means all four implementations,
  `docs/reasons.json`, and the prose counts move together or `make reasons-check` goes red.

---

## Task 3 — Vectors before implementations

The corpus is this project's currency: four implementations agree because the vectors say what the answer is. A
new family (`presentation/…`) with positive cases and, for each failure mode, a negative control: replayed nonce,
stale `created`, moved authority, moved path, altered method, altered body, wrong key, unsigned request under a
policy that requires one.

---

## Task 4 — Implementations, in the order the differential demands

`ainra-core` first (it generates the vectors), then the TS SDK, the Python verifier, the CLI, the middleware.
`make diff` and `make conformance` stay green at every step or the step is not finished.

---

## Task 5 — The payoff: the gate at the edge

Express and a Python gate cover origin servers. Agents are classified at the CDN edge, which is where most of the
traffic is decided, and an edge gate that verifies a signed request is what makes AINRA present where the decision
actually happens.

It is also the interoperability story: RFC 9421 is the layer the agent protocols being announced elsewhere are
built on. Today AINRA meets them with a bespoke header; after M34 it meets them on the layer they already speak.

---

## Task 6 — The texts tell the truth again

`docs/STATUS.md` loses the passport-rung limitation. The Standard says what the code does. The site gains the
one thing a builder currently cannot find: how a request proves itself at the edge.

---

## Not in this milestone

- No new tier, no new class, no registrar feature, nothing that touches P1–P6.
- No change to what the root does. The root still accredits, anchors, revokes and logs.
- No DoD row moves. M34 makes a claim true; it does not make a stranger verify it.

---

## Task 7 — Found by the end-to-end drill: the network does not keep time

`tools/identity-e2e.mjs` runs the whole identity the way a stranger's agent would — its own key, a passport from
the public door, an instance credential, a signed request through a real server running the real gate — at the
**real** clock. It fails, and the reasons are more important than anything else in this milestone:

1. **Every staging delegate certificate expired on 2026-07-09.** The daemon creates each registrar with
   `create_seeded(..., NBF - 3600, NBF, EXP)` where `NBF` is a constant (2026-04-11), so delegates are born on
   2026-04-10 and die 90 days later — on every registrar, on every restart. `deploy/runbooks/key-rotation.md` says
   rotation is "restart with fresh delegates"; for this daemon a restart re-mints the same expired window.
2. **Nothing noticed**, because every check pins the clock: `tools/stage-smoke.sh` sets `NOW` to 2026-04-21, and
   the daily stranger journeys run inside the same frozen window. The staging network has been dead at real time
   for two and a half months while every board stayed green.
3. **A passport outlives the checkpoint its presentation carries.** `present()` returns the checkpoint and
   inclusion proof stored at issuance, signed by that day's delegate. Once the delegate expires (≤92 days), the
   passport is `checkpoint_invalid` — although ADR-017 gives it 366. A presentation has to prove inclusion against
   a CURRENT checkpoint signed by a CURRENT delegate, as Certificate Transparency does.
4. **The write path signs what the read path refuses.** On 2026-09-19 challenge minting against registrar-07 at the
   real clock made the daemon sign revocation deltas with a delegate that had expired two months earlier. It saved
   them, and now refuses to load them (`delta replay: checkpoint_invalid`). Confirmed pre-existing: the binary from
   before D-063 fails identically on a copy of the same state.
5. **Every verifier challenge minted after 2026-07-09 contains no valid passport** — packets 01–08 hold only
   `revoked` and `checkpoint_invalid`. The attestation still binds execution (the revocations are still a secret
   coin flip), but a stranger running the kit sees eight invalid passports and zero valid ones. The certification
   check compares an attestation to the answer key, not to what a challenge is supposed to contain, so the kit
   agreed with itself.

What this needs is its own milestone — the network keeps time: wall-clock operation, delegate rotation before
expiry, presentations against the current checkpoint, a write path that refuses to sign outside its delegate
window, a mint that refuses a challenge with no valid passport, and a board that checks at the real clock.

**Resolved by M35 (D-064).** The daemon renews its delegates at the wall clock, presents every passport and every
hop against the current checkpoint, refuses to sign outside its delegate window, and fails closed on writes. `make
live-up` runs the wall-clock network and `make identity-e2e` passes against it; `make live-status` is the real-clock
check. The staging network stays pinned, on purpose and by name (`AINRA_CLOCK=pinned`). Still open: re-minting the
eight challenges (finding 5), and the 66.7 KiB of request headers the end-to-end run measures.
