<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Witness Kit — a witness quorum you can actually deploy

A single witness catching a fork is trust-in-one-operator. AINRA's fork defence is a **quorum of independently-operated
witnesses** (D-021): a log checkpoint is *certified* only when at least **k** distinct witnesses cosign it, and because
each honest witness refuses to cosign a checkpoint that forks the head it already cosigned, an equivocating fork can't
reach quorum unless **k or more** witnesses are adversarial. M6 proved this in-process; this kit runs it **between
separate processes over HTTP**, so you can put each witness on its own machine.

## Prove it locally
```sh
make drill-networked            # 5 witnessd processes on separate ports, k=3
# → honest head certified (5 cosigns fetched over HTTP); INJECTED FORK refused 5/5 → not certified
make drill-networked N=7 K=4    # any N >= 3, any 1 <= k <= N
```

## The pieces
- **`witnessd <addr>`** — one witness daemon. `GET /key` → its Ed25519 public key; `POST /consider` → it evaluates a
  submitted checkpoint (validly log-signed? append-only vs the head it last cosigned?) and returns its **outcome** and,
  when it accepts, a **cosignature**. Its key is derived from its address so a quorum of daemons have **distinct** keys;
  a real deployment gives each witness an operator-held key on separate infrastructure.
- **`witness-quorum-drill <k> <addr>...`** — a **relying party**: it fetches each witness's key (its roster), submits
  the log's checkpoints, collects the cosignatures over the wire, assembles a `QuorumCertificate`, and checks
  `certified(checkpoint, roster, k)`.

## The one rule that must never bend: **k is the relying party's**
The threshold **k is an argument the relying party supplies** — it is *never* read from anything fetched. The
certificate carries **no threshold field** at all, so an equivocating log that assembles a certificate for its fork
cannot set `k = 0` and "self-certify"; `certified()` also refuses a nonsensical `k = 0`. (This is the M6 review's HIGH
fix — see D-021 — preserved across the network transport. The regression lives in
`services/ainra-services/tests/fork_drill.rs`.)

## Deploying real witnesses
- Run one `witnessd` per operator, each on its own host, behind a reverse proxy terminating **TLS** (the daemon speaks
  plain HTTP by design — transport security + auth are the deployment's job, matching the local-by-default posture).
- Publish each witness's public key so relying parties can build a roster they trust (out of band, or via the log's
  accreditation). Relying parties pick their own **k** from that roster — a payments-grade verifier might demand a
  higher k than a low-stakes one.
- This is deliberately **boring**: fetch + verify, no gossip protocol, no consensus engine (Certificate Transparency's
  gossip never shipped; witness cosigning is the deployed fix — MTS §5). The security is in the signatures, not the
  transport.

## What this closes (and what stays out of scope)
- **Closed:** the witness quorum now runs between separate processes over a network; the §29 "injected fork caught by
  witnesses (not us)" is demonstrable with independently-operated witnesses, not just in-process keys.
- **Out of scope (deployment):** TLS/auth/rate-limiting on the transport, witness discovery, and hardware witnesses —
  standard operational concerns layered on top; the security-relevant logic is all in `ainra-services::witness`.
