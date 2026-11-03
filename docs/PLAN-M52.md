<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M52 — The network control room, the directory workbench, and a hosted network

Written on 3 November 2026 at the owner's request: "our own AINRA control field in the terminal or a control panel,
like ICANN has, and host AINRA somewhere". This plan says what that is, in the shape the constitution allows.

## What ICANN's "control" actually is, and what ours must be

ICANN does not run a panel that hands out names. Its operational core is root-zone *change management* (the IANA
function): a change is requested, checked, shown as a diff, authorized, and only then published — and registries and
registrars, not ICANN, serve the public. AINRA already has that split. Registrars issue, renew and revoke (each has
its open console, D-034); the root's one act is a new **directory epoch** — who is accredited, which delegates are
revoked, where distrust starts — to be signed by the threshold of custodians (FROST 5-of-9 + SLH-DSA), never by one
key and never online. That threshold is rehearsed (`make ceremony-rehearsal-multi`) and has not yet been held for real:
today's root is a TEST-ROOT, and the recorded ceremony is a pending DoD row.

D-034 is a constitutional constraint: *the root gains no console and no self-serve surface.* So the control room is
two things, and neither can act alone:

1. **A control room that only reads.** Everything about the network, verified root-dark from public artifacts, in the
   terminal and as a page — so anyone, not only us, sees what the operator sees.
2. **A directory workbench that only proposes.** It drafts the next epoch and shows its diff; it holds no key. The
   draft becomes the directory only when the custodians sign it in the ceremony kit.

That is "like ICANN" in the way that matters: changes go through a visible process, and no panel is a root.

## The steps

**1. `ainra ctl` — the network in one terminal command.** `ainra ctl status --net <artifact-url>` (and `--watch`):
the directory (epoch, registrars, revoked delegates, distrust cutoffs) verified against the roots; each registrar's
log head, status sequence, fresh-head age and `/witness-feed` reachability; the witness roster and the latest
cosignatures per checkpoint (counted as the genesis board counts them); the genesis board's rows; revocation latency
from the latest soak report; and an alarm line for anything stale, regressing or unverifiable. Read-only, offline
verification, zero telemetry, exit code non-zero on an alarm (so it can be a cron or a CI check). WITNESS: a registrar
serving a smaller log than last seen, a directory older than the one held, and a witness cosigning two roots at one
size must each raise an alarm in a drill.

**2. The control-room page.** The same view as a static page on the site (`/control.html`), reading the public
artifact contract in the visitor's browser with the WASM verifier — no server, no accounts, nothing it can change.
WITNESS: tampered artifacts render as an alarm, never as green.

**3. The directory workbench.** `ainra directory propose` (`--accredit`, `--withdraw`, `--distrust-from <leaf>`,
`--revoke-delegate`) writes an unsigned proposal for epoch N+1 with a human-readable diff against the current
directory and the reasons each change cites; `ainra directory check-proposal` re-derives the diff; the ceremony kit
signs it (threshold, offline); `ainra directory publish` refuses anything not signed by both roots and not newer than
what mirrors hold (D-083). Every proposal and its outcome is logged in a public, append-only record. WITNESS: a
proposal that skips an epoch, drops an entry silently, or is signed by one root only must be refused.

**4. Host the network (the owner decides where).** What has to be public for strangers to take part: the site (done),
the **public read contract** (directory, roots, registry — today a dated static copy at ainra.org/net/, refreshed by
hand from the local staging artifact server), at least
one wall-clock **registrar endpoint** with its `/witness-feed` and demo door (TEST-ROOT, labelled), the **online verifier**
(`services/verify`), and a mirror. The deployment already exists as code (`deploy/compose.*.yml`, `deploy/runbooks/`,
systemd units); hosting is choosing a provider and names, which is the owner's one-way door. Nothing is provisioned on
anyone's account by us. Done means: a stranger's witness polls a public `/witness-feed`, the board counts it, and
`make claims-live` holds the deployment to what the repository says.

**5. Run it like an operator.** The compliance probe and the soak on a schedule against the hosted network; their
reports published; incidents through `deploy/runbooks/incident.md` and the 72-hour disclosure term. WITNESS: a
deliberately degraded registrar is caught by the scheduled probe within one cycle.

## Proposed here, and left to the owner

- Proposed: the control room reads, the workbench proposes, the ceremony signs. No step adds a root key online, a
  root write API, or an account system. (D-088, PROPOSED — the owner rules.)
- The owner's: the hosting provider and region(s); the public names (`registrar-07.<domain>`, `feed.<domain>`, …);
  whether the control-room page ships before the network is hosted (it can read the staging copy, labelled).

## Done means

`ainra ctl status` green against the hosted network from a stranger's machine; the control-room page live; a
directory proposal taken through check → ceremony sign (rehearsal) → publish; each step's negative control shown red.
