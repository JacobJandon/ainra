<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Run an AINRA witness

**The ask:** run a tiny always-on service that co-signs AINRA's log checkpoints, so that no one — including us — can
show you a forked or rewritten history without a quorum of independent witnesses catching it.

## What a witness does
AINRA's transparency log publishes signed **checkpoints** (a Merkle head). A witness fetches each checkpoint, checks it
only ever **appends** (never rewrites or forks), and **cosigns** the ones it accepts. A relying party then trusts a
head only if a **quorum (k-of-N)** of witnesses cosigned it. If we ever tried to equivocate — serve two different
histories — an honest witness refuses to cosign the fork, and the quorum fails. The catch is made by *you*, not us.

## Why it's deliberately cheap
A witness is boring on purpose: it fetches, verifies append-only, signs. No consensus, no gossip, no chain, no coin —
it's the same shape as the C2SP tlog-witness the transparency-log community already runs. It fits on the smallest VM or
a board in a closet. The mechanism is proven: `make drill-networked` stands up N witnesses over HTTP and shows an
injected fork **refused by their quorum, not by us**. Setup + protocol: `kits/witness/`.

## What independence means (and the strong version of the ask)
Your value is that you are **not us**: run it on your own infra, your own key, your own network vantage. The threshold
`k` is always the *relying party's* choice, never read from any certificate we hand out. The strongest thing you can do
for the ecosystem: also point a witness/monitor at a **different** root or log than ours — a witness that watches a
competitor keeps *everyone* honest, which is exactly the neutrality AINRA is built to serve.

## Cost to you
A small always-on process, one keypair, outbound HTTPS. In return you hold a veto over silent history-rewrites. Three
independent operators running witnesses on separate infra is a remaining DoD item (`GENESIS-CHECKLIST.md` §4). Reply and
we'll get you a witness seat and the roster.
