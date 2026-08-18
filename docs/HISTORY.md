<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# How AINRA was built — the milestone ladder

Twenty-four milestone plans, one line each. The plans themselves are in
[`_archive/plans/`](_archive/plans/): they were working documents, accurate on the day they were written, and they
are kept unedited because a plan rewritten after the fact is not a record of anything.

**If you want to know what the system does today, do not read these.** Read [`STATUS.md`](STATUS.md) for the
component-by-component state, [`DECISIONS.md`](DECISIONS.md) for every deliberate deviation with its reasoning, and
the [normative spec](AINRA_Master_Technical_Specification_v1.md), which wins conflicts. This file exists so that
"why is it like this?" has one place to start.

## M1–M9 · the engineering ladder

| | | |
|---|---|---|
| **M1** | [`ainra-core` skeleton, schemas, vectors v1, CI/fuzz scaffolding](_archive/plans/PLAN-M1.md) | the verify library and the corpus everything else is measured against |
| **M2** | [execution plan](_archive/plans/PLAN-M2.md) | the working method itself — ≤15 bullets per milestone |
| **M3** | [TSL delta stream + registrar-in-a-box + `ainra-cli-rs`](_archive/plans/PLAN-M3.md) | revocation became a stream, and a registrar became runnable |
| **M4** | [FROST threshold root + dual-root directory + delegate revocation](_archive/plans/PLAN-M4.md) | no single key is the root |
| **M5** | [the verification wedge: SDK GA + middleware + live testbed](_archive/plans/PLAN-M5.md) | the five-line verifier — the thing anyone actually integrates |
| **M6** | [adversarial program + multi-witness fork drill](_archive/plans/PLAN-M6.md) | a fork is refused by a quorum, not by us |
| **M7** | [reproducible builds + mirrors + docs freeze](_archive/plans/PLAN-M7.md) | artifacts rebuild byte-exact; normative docs stop moving |
| **M8** | [`make genesis-local` + the Genesis DoD](_archive/plans/PLAN-M8.md) | the whole world on one laptop |
| **M9** | [commit, public-ready, executable by strangers](_archive/plans/PLAN-M9.md) | the clone-and-it-works promise |

## M10–M17 · public, operational, honest

| | | |
|---|---|---|
| **M10** | [publish-ready + stranger-completable DoD events](_archive/plans/PLAN-M10.md) | the four external rows became things a stranger can run unattended |
| **M11** | [public-operational: plumbing, durability, operator tooling](_archive/plans/PLAN-M11.md) | |
| **M12** | [validity & renewal — ADR-017](_archive/plans/PLAN-M12.md) | identity eternal, credentials bounded, renewal invisible |
| **M14** | [the staging network on the internet, honestly labeled](_archive/plans/PLAN-M14.md) | `STAGING · TEST-ROOT` printed on everything it touches |
| **M15** | [Genesis Day: runbook, gates, fail-closed declaration, rehearsal](_archive/plans/PLAN-M15.md) | |
| **M16** | [the onramp](_archive/plans/PLAN-M16.md) | `make verify` / `make issue-first`, the MCP server, `skills.md` |
| **M17** | [the public face becomes real](_archive/plans/PLAN-M17.md) | the site, and the public demo door a stranger can complete in a browser |

## M23–M27 · hardening under real conditions

| | | |
|---|---|---|
| **M23** | [Suite Migration Drill 01](_archive/plans/PLAN-M23.md) | migrating a signature suite while live, rehearsed |
| **M25** | [state audit · M24 close · the front door](_archive/plans/PLAN-M25.md) | |
| **M26** | [the ml-dsa advisory, taken properly](_archive/plans/PLAN-M26.md) | a real timing side-channel in a direct dependency — and the reason `cargo audit` now reports everything before it gates, so one notice can never hide another |
| **M27** | [the staging network stands, and a stranger walks the whole surface](_archive/plans/PLAN-M27.md) | systemd user units, linger, a watchdog — and the honest claim that goes with them: *runs whenever this machine is on* |

## L1–L5 · launch and the human half

| | | |
|---|---|---|
| **L1** | [the launch session](_archive/plans/PLAN-L1.md) | the repository went public; signed tags at pinned commits; the stranger test, 18/18, from a credential-less container |
| **L2** | [operational scaffolding for a public root](_archive/plans/PLAN-L2.md) | |
| **L3** | [the human half gets a sequence, and published counts get a gate](_archive/plans/PLAN-L3.md) | |
| **L4** | *(no plan file — worked directly)* | v0.3.2 published end to end; the five jurisdiction premises verified against primary sources, deciding nothing |
| **L5** | [one decode path, and a WASM surface that uses it](_archive/plans/PLAN-L5.md) | `make one-decode-path` fails the build if a second parser appears anywhere |

## After the ladder — the settlers pass

Not a milestone. [`SETTLERS.md`](SETTLERS.md) audited what comparable efforts — certificate authorities, transparency
logs, DNSSEC, the DID working group — were forced to admit publicly, and asked which of those arrows AINRA was still
walking into. Five of its seven recommendations shipped:

- **[D-044](DECISIONS.md)** — graduated distrust keyed on **log position**, not a date. The web PKI keyed it on
  `notBefore` and a CA backdated to evade it; a log index cannot be backdated.
- **[D-045](DECISIONS.md)** — a log may never come back **shorter** than it has already been. A CT log auto-restored
  from a stale backup and published a tree head inconsistent with its own earlier ones.
- **[D-046](DECISIONS.md)** + **[PROBES.md](PROBES.md)** — compliance measured **adversarially**, by a probe holding
  nothing the registrar issued it. Every regime that asked operators whether they complied was corrected from outside.
- **[DISCLOSURE.md](DISCLOSURE.md)** — 72 hours, no severity threshold. The 2011 CA removal listed *"failure to
  notify"* ahead of the breach itself.
- **[genesis-day/ROLLBACK.md](genesis-day/ROLLBACK.md)** — we can never measure how many verifiers hold a given root,
  because the charter forbids the telemetry that would tell us. So reversibility is over-engineered instead.

Its two open recommendations are the two that were never code: the instance-credential rung (a design decision), and
**witnesses** (people).
