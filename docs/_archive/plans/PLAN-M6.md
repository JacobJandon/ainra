<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M6 — adversarial program green + multi-witness fork drill (playbook wk10)

M6 turns "we catch our own forks" into "**they** catch forks" — an injected log fork must be refused by an
independent **witness quorum**, not by us. Alongside it: close the residual **fresh-head currency** gap the M5
review flagged (LOW), and run the **full-repo adversarial + fuzz** sweep. Exit (MTS §27/§29 DoD): differential
parity 100%, **a fork caught by a ≥3-of-N witness quorum**, fresh-head bound into the GA path, fuzz budget met.

Standing rules unchanged: facts never scores · both sigs or invalid · logged-before-valid · fail closed · the
verify path is static and scales by *addition* · `ainra-core` pure (N7) · no real company names (S7) · every
deviation in `DECISIONS.md` · end with `make ci` green + honest `STATUS.md`.

## Thread A — the multi-witness fork drill (headline)

Today one `Witness` (witness.rs) cosigns append-only growth and refuses an equivocating fork (`RefusedFork`);
`make drill` (pipeline-demo) + `tests/fork_drill.rs` prove it single-witness. M6 lifts this to a **quorum**:

- **`WitnessQuorum`** — N independently-keyed witnesses + a `threshold` k. `certify(cp, sig, now, proof)` presents
  the checkpoint to every witness and collects the cosignatures of those that accept it, into a verifiable
  **`QuorumCertificate`** (`(witness_pubkey, cosig)` pairs). A relying party verifies each cosignature against a
  known witness-key set; the head is **certified** iff ≥ k *distinct known* witnesses cosigned.
- **The catch is theirs:** once the quorum certifies the honest head at size N, an equivocating fork at size N
  (valid log signature, different root) is refused by every honest witness that already saw the honest root — so it
  gathers < k cosignatures and **cannot be certified**. Demonstrated for N=5, k=3.
- **Byzantine tolerance (f < k):** even with f adversarial witnesses that cosign the fork, the fork gets ≤ f < k and
  still fails to certify, while the honest head still reaches k. The drill shows N=5, k=3, f=2 → fork = 2 < 3.

Deliver: `WitnessQuorum`/`QuorumCertificate` in witness.rs (with `verify`); extend `make drill` (pipeline-demo) to
show the quorum catch; multi-witness assertions in `tests/fork_drill.rs`.

## Thread B — fresh-head currency binding (closes the M5 review LOW, honestly)

The M5 review's residual LOW: a stateless offline verifier trusts a genuine, registrar-signed status **snapshot**
within its freshness window, so a holder can replay a pre-revocation snapshot until it ages out. The SDK already has
`verifyFreshHead`/`headHash` (used only in the delta corpus). M6 wires them into the GA path:

- The `/present` bundle carries the registrar's **delegate-signed fresh head** (`FreshHead`: uri, seq, ts,
  status_hash, sig). The GA `Verifier` verifies the fresh head (delegate cert → log root, sig, F-class recency) and
  **binds** it to the presented status list (`headHash(uri, bit_len, status_list) == fresh_head.status_hash`).
- **Honest scope (no overclaim):** a fresh head lets the verifier bind the list to a signed head *identity* and
  tightens the practical window (the registrar republishes a fresh head every ≤30 s, so the freshest available is
  F1). It does **not** by itself make a *stateless* verifier immune to replay within the window — that is the
  fundamental limit of offline stapled verification. Full currency is an **opt-in stateful mode**: a verifier that
  remembers the highest `seq` it has accepted per uri rejects any lower-seq fresh head (monotonic-seq), fully
  closing replay for that verifier. Both are shipped; neither is oversold.

Deliver: fresh head in the `/present` bundle; `Verifier` fresh-head verify + head-hash binding (+ optional
monotonic-seq state); regression tests; parity unchanged (this is GA-layer, not the frozen verify).

## Thread C — adversarial program + fuzz budget

- Run the **full-repo adversarial workflow** (all milestones M1–M6), triage + fix confirmed findings (the M5
  status-auth pass is the template).
- Grow the **fuzz corpus** toward budget: the three targets (`canon`, `passport`, `tsl`) get seed corpora +
  a longer `fuzz-smoke` run; add a `witness`/quorum target if the surface warrants.

## Sequencing (each verified before the next)

1. **A** WitnessQuorum + drill + tests → `make drill` + `cargo test` green.
2. **B** fresh-head binding + regressions → wedge-test + diff parity green.
3. **C** adversarial sweep + fuzz → fix findings, `make ci` green.
4. Update `DECISIONS.md` (D-021), `STATUS.md`, `PLAN.md`; honest report. Plan M7 (reproducible builds + mirrors)
   and M8 (`make genesis-local` + Genesis) forward.

## What M6 deliberately does NOT do (recorded, not faked)

- No live witness *network* daemon/gossip transport — the quorum is demonstrated in-process with real independent
  keys + real cosignatures (the transport is deployment work, M7+). The security property (fork can't reach quorum)
  is real and tested; only the wire transport is out of scope.
- No claim that a stateless verifier achieves zero-latency revocation — freshness bounds latency; the honest bound
  is documented (Thread B).
