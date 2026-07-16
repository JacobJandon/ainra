<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M3 — TSL delta stream + registrar-in-a-box + `ainra-cli-rs`

M3 per MTS §27 / ADR-007: the **signed status delta stream + 30-second fresh head**, a **real registrar-in-a-box**
(issue → log → revoke), the **`ainra` reference CLI**, and a **registrar explorer** — all over the same audited
`ainra-core`, all cross-checked by the independent `sdk-ts` mirror. Prime directive unchanged: **nothing fake**
(brief §0). Every verdict shown anywhere is the real verifier's; every signature is real hybrid + SLH-DSA.

## What M3 delivered (all green under `make`)

1. **Signed status deltas (`ainra-core::status`).** `StatusDelta { uri, from_seq, seq, ts, idx[], new_status,
   sig_registrar, countersig_delegate }` (spec §202). A delta advances the head by **exactly one** sequence number
   and is authorized by BOTH the registrar's hybrid key AND a root-certified online delegate (scope
   `delta-countersign`, ADR-002) — both-or-invalid, fail closed. Two failure planes, two reasons kept distinct:
   delegate-chain failures → `checkpoint_invalid`; structural / registrar-sig failures → `stale_status` (the head
   cannot be advanced from trusted material → status unavailable → fail closed to stale, never valid). `apply`
   bounds-checks every index *before* mutating (no half-apply) and re-checks head linkage.

2. **Fresh head (ADR-007's F1 heartbeat).** `FreshHead { uri, seq, ts, status_hash, sig_delegate }` — a tiny
   delegate-signed statement (scope `fresh-head`) of the head's SHA-256 identity as of `ts`. Verified: cert chains
   to root + delegate signature + freshness (F1 ≤ 30 s). `binds()` confirms the head names the list a verifier
   actually holds. Closes the withheld-list/stream window: no fresh head within the class window ⇒ fail closed.

3. **`registrar-box` (`services/ainra-services::registrar`) — spec C5.** A real registrar that composes the audited
   primitives + the M2 daemons: one hybrid issuer key + one SLH-DSA ceremony-root stand-in (certifies the log's
   checkpoint delegate AND the status segment's delta/fresh-head delegate); **issue** builds the SD-JWT-VC claims,
   dual-signs any delegation hops, appends the credential body + each hop's bytes to its own `logd` shard, snapshots
   + delegate-signs a checkpoint, and keeps the RFC 6962 inclusion proof (logged-before-valid at issue time);
   **revoke** flips the lineage bit through the `statusd` segment, emitting a signed, delegate-countersigned delta;
   **datastore** keeps every credential as a self-describing `IssuedRecord` (all binary base64url) that round-trips
   to disk and reconstructs a verifiable `Presentation`. Verdicts come from calling `ainra_core::verify::verify`.
   Deterministic **reload** (`create_seeded` + `load`): the same seed regenerates byte-identical keys, the log tree
   rebuilds from `entries.log`, records reload, and stored deltas replay — so a persisted registrar restarts offline
   with revocations intact. HTTP daemon (`registrar-box` bin): issue / verify / revoke / status-list / fresh-head /
   deltas / export, local + zero-telemetry.

4. **`ainra` CLI (`crates/ainra-cli-rs`).** Offline + persistent (no daemon required): `init · accredit · issue ·
   list · verify · log-verify · revoke · present · status · fresh-head · deltas · export`, each driving the real
   engine. `seed` builds the fictional registry the explorer loads (and self-checks every record with the core
   verifier); `reverify` re-checks an export with the pure core verifier (a third-party check); `demo` runs the
   whole lifecycle in one process, zero setup.

5. **Fictional seed registry.** 3 registrars · 6 operators · 12 lineages across tiers L0–L4 and auth classes A1/A2 ·
   2 delegation trees (owner→desk→bot; buyer-owner→procurement) · 3 revocations. Realistic in shape, zero real
   identity (every operator a neutral placeholder; S7-clean). Every verdict computed by the real verifier.

6. **Registrar explorer (`apps/registrar-explorer`).** A genuinely functional single-file app over the signed
   export: live search (subject/operator/lineage/capability), filters (registrar/tier/auth/status/delegated),
   sortable columns, URL-deep-linked state, a detail panel with the identity, the visualized narrowing delegation
   chain, the transparency-log anchor, and the **9-step verification trace** — each step labelled `re-checked` (the
   browser re-ran the policy invariant live) or `core-verified` (the heavy crypto was verified by the Rust core;
   result carried in the signed export). A revoke workflow that hits the live daemon when configured (CORS-enabled)
   or runs over loaded state otherwise, and a re-verify-at-time-T control.

7. **Cross-implementation ripple.** `statusd` gained the delta/fresh-head endpoints. `sdk-ts` gained `verifyDelta` /
   `verifyFreshHead` mirroring the core exactly. `vector-gen` emits a **14-vector delta/fresh-head corpus**
   (`vectors/v1-delta/`) — real crypto, every accept + reject reason, expected computed by the real core — and the
   diff harness gained **phase (D)**: `runDeltaVector` (sdk-ts) vs the core-baked expected, **14/14 agree**.

## Deliberately deferred (recorded, not faked)

| Item | Why later |
|---|---|
| Delegate-cert **rotation** across 90-day windows | The prototype's demonstrated timeline sits inside one delegate-cert window; live rotation + checkpoint re-anchoring via consistency proofs is M4 operational work. A credential's 1-year validity and the checkpoint delegate's ≤ 92-day cert are independent by design (ADR-002). |
| Dynamic (AP2) mandates | Still M3-reserved in the passport schema and still fail-closed rejected (D-013). The delta stream is orthogonal; binding an operative mandate needs the AP2 object model. |
| FROST threshold delegate/root, Tessera storage, witness onboarding | Verification-identical stand-ins ship now (D-005/D-011); the real ceremony + storage swap are M4–M8. |
| `registrar-box` multi-region / auth / persistence hardening | The reference is a working single-host issuer, not the hardened deployment. |

## Adversarial review (post-build)

A 6-dimension review swept the M3 surface (delta codec · registrar engine · reload/persistence · daemons/HTTP ·
sdk-ts parity · vectors/fakeness): **12 candidate findings**, every real one fixed and gate-tested — most notably
the reload path replaying status deltas **without re-verifying signatures** (fail-open on a tampered snapshot; now
the full core `StatusDelta::verify` runs per replayed delta, the head sequence is cross-checked against the
persisted `status_seq`, and `tampered_snapshot_is_refused_fail_closed` pins both), fabricated holder key material
in issued credentials (now a real hybrid holder keypair + real SHA-256 `cnf.jkt` in every credential, registrar +
samples), the reload seed sharing a file with the exportable snapshot (now a separate 0600 `registrar.secret`),
sdk-ts failing open on an unknown freshness class, an unbounded `Content-Length` allocation, and delta-corpus
coverage gaps (now 17 vectors + `--check-delta` replay-gated locally and in CI). Full list in STATUS.md.

## Gates (the acceptance bar, MTS §28)

`make test` (67 core unit + 10 property + 8 registrar + 3 service) · `make vectors` (660 passport + 17 delta,
self-checked, replay-gated) · `make diff` (A 660/660 verdicts, B 10/10 canon, C 4/4 reject, **D 17/17 delta**) ·
`make drill` (M2 pipeline + fork) · `make demo` (M3 lifecycle) · S7 / license clean · `cargo fmt`/`clippy -D
warnings` clean. See STATUS.md.
