<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Be an independent AINRA verifier

**The ask:** spend ~10 minutes confirming, on your own machine, that AINRA's root actually works — then send back one
signed file. That's it.

## What you'd do
1. We mint you a **challenge** (a small folder of fresh artifacts) and send it over. One challenge per person.
2. You run one command (`make verify-as-external CHALLENGE=<folder>`) using only the published `@ainra/sdk`.
3. It verifies — with the **root offline** — that a genuine passport is valid, a revoked one is rejected, a forged
   all-clear can't un-revoke it, and that your fresh challenge bundles get the right verdicts.
4. You send back `verifier-attestation.json`. **Nothing else leaves your machine** (the kit makes no network calls;
   your signing key is a throwaway).

Full steps: `kits/verifier/QUICKSTART.md`. Stuck: `kits/verifier/TROUBLESHOOTING.md`.

## What your attestation publicly means
That a party holding your key **actually performed AINRA verification** on inputs you couldn't have precomputed —
independent confirmation the system does what it claims, root-dark. Stated precisely so no one overstates it: it does
**not** prove you ran our exact binary (a conformant reimplementation would also pass), and it isn't a proof of
personhood. Your standing as a *distinct* verifier comes from us issuing you your own challenge, out of band. (This is
the honest scope from `DECISIONS.md` D-024 — we won't claim more from your work than it shows.)

## Why it matters
The whole point of a neutral root is *verify, don't trust* — including not trusting us. Three unaffiliated people, on
three machines, each independently reaching the correct verdicts is one of the last things standing between the
prototype and a founded root (`GENESIS-CHECKLIST.md` §3). You'd be one of them.

## Cost to you
~10 minutes, one machine, no account, no data shared, no ongoing commitment. Reply and we'll send a challenge.
