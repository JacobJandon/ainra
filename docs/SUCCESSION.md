<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Succession — what you inherit, and what nobody can hand you

Today AINRA is operator-run. If the operator stops, everything stops — and the failure mode is not that the site
goes down. It is that the site **stays up and slowly becomes a lie**: artifacts stop being refreshed, the freshness
stamps age, and pages keep asserting a present tense that is no longer true. A root of trust that decays silently
is worse than one that visibly ends.

This document is written for a stranger. If you are reading it because the previous operator is gone, you are the
intended audience, and nothing here assumes you ever spoke to them.

---

## 1. What you inherit

| | What it is | Where it is | Form |
|---|---|---|---|
| **The repository** | everything — code, corpus, docs, gates, this file | `github.com/JacobJandon/ainra` | public git |
| **The published record** | the site and the agent-readable surface | `ainra.vercel.app` | static, rebuilt from the repo |
| **The site deploy path** | a *second* repo the host watches | `github.com/JacobJandon/ainra-website` | push-to-deploy |
| **The release path** | signed tags + release artifacts | `make release` → `scripts/release.sh` | git tags, GitHub releases |
| **The reproducibility proof** | every published artifact, hashed | `MANIFEST.sha256` | in-repo, `make repro` regenerates |
| **The network** | a local, self-contained instance | `make genesis-local` | ephemeral, no external state |
| **The release signing key** | signs tags and artifacts | offline, outside the repo (D-042) | passphrase-less by policy |
| **Verifier answer keys** | private ground truth for challenges | gitignored, per-party | one file per issued challenge |
| **The candidate tracker** | people in the outreach campaign | `campaign/tracker.local.json` | gitignored, never in git (D-036) |

**The two repositories catch people out and it is worth stating twice.** Pushing to the main repository does not
update the site. `bash tools/export-site.sh` builds the site and pushes it to the *website* repository, which the
host watches. `make deploy-current` is the check that tells you whether what is served matches what the repository
builds — run it after every deploy, and believe it over your memory.

## 2. Your first week

Do these in order. Each is a command, and each either works or tells you why not.

1. **Prove the repository is intact without trusting anyone.** `make preflight` from a *cold clone*. Every gate
   runs. If it is green, everything below is standing on something real.
2. **Prove the artifacts are what they claim.** `make repro && make mirror && make verify-mirror`. This rebuilds
   every published artifact, assembles the mirror, and byte-compares it against `MANIFEST.sha256`.
   (`make mirror` is not optional — `verify-mirror` has nothing to verify without it. The first run of
   `make succession-drill` failed on exactly this, because this document said otherwise.)
3. **Bring the network up locally.** `make genesis-local`. This needs nothing external — no keys you do not have,
   no service anyone must grant you.
4. **Read the published record against the repository.** `make deploy-current` and `node tools/claims-live.mjs`.
   These tell you whether the live site is currently telling the truth.
5. **Read the state of the world honestly.** `make genesis-status` (which Definition-of-Done rows are met),
   `node tools/campaign.mjs status` (what human work is outstanding), `docs/STATUS.md`.
6. **Understand what you may and may not change.** [GOVERNANCE-AMENDMENT.md](../GOVERNANCE-AMENDMENT.md). Six
   prohibitions are unamendable. If you disagree with them, the honest path is a fork under a different name.
7. **Decide, and say so publicly.** Continue, hand on, or wind down. The one option that is not available is
   silence — see §4.

If step 1 fails on a clean clone, that is an inheritance defect, not your mistake. `make succession-drill` exists
to find those before you have to.

## 3. What is impossible to inherit — and why that is a feature

**The root ceremony keys cannot be handed to you.** After genesis they are threshold-held by independent
custodians; no single party holds a usable key, and there is nothing to inherit because there is no whole thing to
pass on. A successor cannot sign as the root by acquiring a laptop, a password manager, or an estate.

This is the property that makes the root worth trusting, and it is the same property that makes succession
awkward. Both halves are true at once, and a document that promised smooth continuity here would be describing a
system with a single point of compromise.

What a successor can do is operate everything else — the repository, the corpus, the gates, the site, the release
path — and convene the custodians. What no successor can do is *become* the root.

*Today, pre-genesis, this is not yet the case:* the current root is operator-generated and therefore inheritable,
which is exactly why the recorded ceremony is a Definition-of-Done row and not a nicety.

## 4. Degrading honestly instead of pretending

The site must tell the truth when nobody is maintaining it. Not a dead-man switch that takes it down — a **stated
staleness horizon** past which the surfaces say what they actually know.

- Every published record carries a stamp of when it was produced.
- Past the horizon in `docs/STALENESS.md`, dependent surfaces state the age rather than implying freshness.
- Well past it, they say **unmaintained since &lt;date&gt;** — from the data, with nobody editing copy.

This is proven by a clock-shifted drill rather than asserted: `make staleness-drill` fast-forwards the stamp and
checks that the surfaces change what they say on their own.

The reason this matters more than uptime: a stale page that looks current is an active lie told to someone
deciding whether to trust an identity system. An honest "unmaintained since 2029-04" costs the project its
reputation for being alive, and keeps its reputation for being truthful. That is the correct trade for a root.
