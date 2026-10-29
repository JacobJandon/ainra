<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M48 — The rework after the 28 October landscape check

Written 2026-10-28. PLAN-M47's first four steps are done (Link, its corpus and live drill, decision records). This
plan finishes the rest, adds what the 28 October research changed, and records the owner's answers. Sources are in
`docs/LANDSCAPE.md` § "Agents that must trust strangers".

## What the research changed

- **The question everyone is asking is "is the other agent telling the truth?"** A new university centre, with
  public research funding, answers it with proofs that a *claim* is true. AINRA answers the question underneath:
  *who* is accountable for the key that made the claim, and is that still so. A proof from a revoked or unattributable
  key is worth little. That is the layering to state, in copy and in conversations: proof of what was said needs
  proof of who said it.
- **Agent networks are shipping identity without revocation.** One agent network with on-chain identity, discovery
  and payments describes no revocation or reputation mechanism. Link can carry its agents' keys across networks once
  it takes more than Ed25519 (deferred, below).
- **Compliance evidence tools stop at "how the system was built".** One open tool signs AI Act documentation records;
  none of it records what a gate decided at the moment of access, and none of it revokes. Decision records fill that
  part, and the two do not compete.
- **Long-lived credentials need post-quantum signatures from day one.** An outside article on passports makes the
  argument AINRA's hybrid design already acts on. One sentence of copy, no change to the design.
- **A public research programme funds open tooling for agents' coordination, on a rolling basis.** It is a second
  funding route after NLnet, with line items kept distinct.

## The owner's answers (28 October)

| # | Question | Answer |
|---|---|---|
| 1 | Pushing | After each green step, the changed CI jobs first run from a clean clone |
| 2 | Staging registrars on the old binary | Restarted on the fixed one; 30 + 3 revocations intact (done) |
| 3 | The site's WASM file | Rebuilt in the repo; deploying is separate |
| 4 | Key for the standard status format | The Ed25519 half of the registrar's status key; no directory change |
| 5 | 0.6.0 published-surface cleanup | Build it all; the owner publishes 0.5.0 first |
| 6 | Public demo door for links | Later, kept on the list in PLAN-M47 § Later |
| 7 | Online verifier | Static artefacts first; the hosted API once a host is chosen |
| 8 | Website | No rework-driven site changes; the contact address was asked for and is in (bbf74f6) |
| 9 | Internet-Draft contact | info@ainra.org |
| 10 | NLnet draft refreshed | Yes (done; the owner submits) |
| 11 | Publish 0.5.0 | Yes (the owner, with npm and PyPI credentials) |

## The rework, in order

1. **Push** the six commits once the clean-clone CI run is green.
2. **Follow-ups.** The 15 one-time follow-ups are rewritten as new emails from info@ainra.org and are in the desk;
   the owner sends them, at most four a day, after the push (they link to files the push publishes).
3. **Finish the gates.** *Done 2026-10-29:* link mode in the Node, edge and Python gates; decision logs on all three;
   `ainra link`, `link-revoke`, `links`, `verify-link`; the MCP tool `ainra_verify_link`; `make link-parity`, the
   three gates on one battery (CI).
4. **The standard status format.** *Done 2026-10-29:* `GET /status-list.jwt`, `ainra status-jwt`, and `kits/tsl`,
   where independent Token Status List and JOSE implementations verify and read it (CI). Originally: Each registrar also serves its list as a signed `statuslist+jwt`; an independent
   open-source Token Status List library reads AINRA's list in a new kit, and CI runs it.
5. **The online verifier, static first.** *Done 2026-10-29 (code and configuration; nothing provisioned):*
   `tools/publish-static.mjs`, `services/verify` with its Dockerfile, `docs/ONLINE-VERIFICATION.md`,
   `make online-verifier-check` (CI). Originally: A publisher writes content-addressed status lists, link indexes and
   checkpoints that any mirror can serve; a stateless `POST /v1/verify` returns a signed decision record; a doorbell
   stream announces new heads; aggregate counters only. Code and deploy configuration; nothing is provisioned.
6. **The pilot kit.** *Done 2026-10-29:* `kits/pilot` (link mode drilled live in `make pilot-e2e`, in live-drills;
   passport mode wired but not yet drilled). Originally: One command puts a link-mode gate with a decision log in front of any endpoint.
7. **0.6.0 surfaces.** The conformance entry points, the MCP tool without fixture mode, trusted and presented inputs
   as different types. Breaking for package users; the owner publishes.
8. **The Internet-Draft.** Status and attribution for externally issued agent keys, with info@ainra.org as contact;
   the owner submits.
9. **Copy.** The "who stands behind the key that made the claim" line, in the outreach now and proposed for the site
   when the owner reopens it.

Each step ends green on preflight, the audit and the changed CI jobs from a clean clone, is committed, and is pushed.

## What does not change

The frozen normative documents, `reasons.json`, every existing corpus, the published packages until the owner
publishes, the live site beyond what the owner asks for, and the rule that the owner sends every message.
