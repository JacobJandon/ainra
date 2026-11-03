<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Run an AINRA witness

**The ask:** run a tiny always-on service that co-signs AINRA's log checkpoints, so that no one — including us — can
show you a forked or rewritten history without a quorum of independent witnesses catching it.

## What a witness does
AINRA's transparency log publishes signed **checkpoints** (a Merkle head). Each checkpoint is submitted to your
witness, which checks it only ever **appends** (never rewrites or forks) and **cosigns** the ones it accepts. A relying
party then trusts a head only if a **quorum (k-of-N)** of witnesses cosigned it. If we ever tried to equivocate — serve
two different histories — an honest witness refuses to cosign the fork, and the quorum fails. The catch is made by
*you*, not us.

Where this stands today: **zero independent witnesses**, and the seats are open. The witness you would run is
ready for a stranger: one command (`kits/witness/be-a-witness.sh`) gives it a random key of its own, a memory that
survives restarts, and every log key from the root-signed directory published at https://ainra.org/net/;
`kits/witness/submit.mjs` feeds it the registrar's signed checkpoint with the consistency proof and keeps your
cosignature as evidence the public genesis board counts — never under a key we run. `make witness-feed-drill` proves
the path end to end. What is not ready is on our side: the published directory is the staging network's, whose
registrars bind `127.0.0.1`, so until the network is hosted (PLAN-M52) there is no live feed for an outside witness to
poll (`deploy/witness-quickstart.md`).

## Why it's deliberately cheap
A witness is boring on purpose: it verifies append-only, then signs. No consensus, no gossip, no chain, no coin —
it's the same shape as the C2SP tlog-witness the transparency-log community already runs. It fits on the smallest VM or
a board in a closet. The mechanism is proven: `make drill-networked` stands up N witnesses over HTTP and shows an
injected fork **refused by their quorum, not by us**. Setup + protocol: `kits/witness/`.

## What independence means (and the strong version of the ask)
Your value is that you are **not us**: run it on your own infra, your own key, your own network vantage. The threshold
`k` is always the *relying party's* choice, never read from any certificate we hand out. The strongest thing you can do
for the ecosystem: also point a witness/monitor at a **different** root or log than ours — a witness that watches a
competitor keeps *everyone* honest, which is exactly the neutrality AINRA is built to serve.

## Cost to you
A small always-on process, one keypair, and a TLS-fronted endpoint. In return you hold a veto over silent
history-rewrites. Three independent operators running witnesses on separate infra is a remaining DoD item
(`GENESIS-CHECKLIST.md` §4), and the board moves only on what your witness signed (`evidence/README.md`). To take a
seat on the roster, open a pull request adding the candidacy file `be-a-witness.sh` prints
(`evidence/witness/<your-id>.json`); CI checks its shape and probes your endpoint.
