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

## Run your own witness (v2 — one binary, one file)
```sh
cargo build --release -p ainra-services --bin witnessd
cp kits/witness/witness.config.json my-witness.json     # edit operator/region/contact/note; set/remove `seed`
./target/release/witnessd 0.0.0.0:4991 my-witness.json   # config is OPTIONAL — `witnessd 0.0.0.0:4991` still works
make witness-check                                        # v2 smoke + a TIMED <10-min onboarding rehearsal
```
- **`witnessd <addr> [config.json]`** — one witness daemon, one binary, no runtime deps.
  - `GET /key` (alias **`/root`**) → its Ed25519 public key.
  - `GET /meta` → the operator's **self-declared** card `{ self_declared: true, ed25519, operator, region, contact, note }`.
    **Verified by no one** — the key is the only cryptographic fact; the site and verifier render the rest as an
    unverified operator claim. Witnessing needs **no accreditation**.
  - `POST /consider` → it evaluates a submitted checkpoint (validly log-signed? append-only vs the head it last
    cosigned?) and returns its **outcome** and, when it accepts, a **cosignature**.
  - Key: a config `seed` pins a persistent operator key; otherwise it is derived from the address so a quorum of
    daemons have **distinct** keys — a real deployment gives each witness an operator-held key on separate infra.
- **`witness-quorum-drill <k> <addr>...`** — a **relying party**: it fetches each witness's key (its roster), submits
  the log's checkpoints, collects the cosignatures over the wire, assembles a `QuorumCertificate`, and checks
  `certified(checkpoint, roster, k)`.

## Choosing your quorum k (worked examples)
`k` is **your** risk tolerance, not the network's. With `N` witnesses on the roster, a checkpoint is certified once
`k` distinct ones cosign. Two failure modes pull `k` in opposite directions — **safety** (can a fork be certified?)
needs `k` *high*; **liveness** (can honest witnesses still certify?) needs `k` *low*:

| Your roster | k | A fork needs… | You still certify if… | Fits |
|---|---|---|---|---|
| N=3 | **2** | 2 of 3 witnesses collude | any 2 are honest + reachable | a small deployment, low stakes |
| N=5 | **3** | 3 of 5 collude | any 3 of 5 up | the default staging shape (`make drill-networked`) |
| N=7 | **5** | 5 of 7 collude | any 5 of 7 up | payments-grade: tolerates 2 down AND resists 4 malicious |
| N=5 | 1 | **one** rogue witness equivocates | any 1 up | ✗ too low — one bad witness certifies a fork |
| N=5 | 5 | all 5 collude | **all 5** up | ✗ too high — one witness offline halts you |

Rule of thumb: pick the largest `k` whose "you still certify" column you can operationally sustain. A fork is then
uncertifiable unless **k** witnesses are simultaneously adversarial — you buy safety up to your liveness budget. `k`
travels with the *verifier's* config, never with a credential or a certificate (below).

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
- Fill in `/meta` (operator, region, contact) so relying parties and the explorer can see **witness diversity** — how
  many independent operators, in how many regions, stand behind a checkpoint. It is self-declared and rendered as
  such; diversity is a *social* fact the metadata surfaces, never a cryptographic claim the protocol enforces.
- This is deliberately **boring**: fetch + verify, no gossip protocol, no consensus engine (Certificate Transparency's
  gossip never shipped; witness cosigning is the deployed fix — MTS §5). The security is in the signatures, not the
  transport.

## What this closes (and what stays out of scope)
- **Closed:** the witness quorum runs between separate processes over a network; the §29 "injected fork caught by
  witnesses (not us)" is demonstrable with independently-operated witnesses, not just in-process keys. v2 makes the
  daemon a **one-file-config single binary** with a self-declared `/meta` card, and `make witness-check` times the
  full clone→running-witness path (well under the 10-minute onboarding bar the kit promises).
- **Out of scope (deployment):** TLS/auth/rate-limiting on the transport, witness discovery, and hardware witnesses —
  standard operational concerns layered on top; the security-relevant logic is all in `ainra-services::witness`.
