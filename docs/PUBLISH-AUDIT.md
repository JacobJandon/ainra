<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PUBLISH AUDIT — is this repo safe to make public?

Scope: the repo is about to become public, so this audits the **full 24-commit history**, not just the working tree
(a secret or private doc in an early commit is public even if deleted later). Status as of M10 Task 1.

**Verdict: 0 secrets. Private strategy material + a legacy archive were in the committed history; the owner chose
Option A (surgical rewrite + relocate). Executed: the private docs (`AINRA_Master_Plan_v1.md`,
`AINRA_Launch_Readiness_Plan.md`, `PLAN.md`) + `_archive/` are relocated to the sibling `../ainra-private/` and
excised from ALL history via `git filter-repo`; the code-cited MTS is kept and lightly scrubbed of its internal
framing. After the rewrite the whole tree is brand-clean.**

---

## 1. Secrets — CLEAN ✅

- **gitleaks over all 24 commits: 672 findings, ALL false positives.** Every hit is `generic-api-key` firing on the
  high-entropy base64 of **public** key fields in the CC0 test vectors — `log_root_key` (43 b64url chars = 32-byte
  ed25519 **public** key) and `issuer_key.{ed25519,mldsa65}` (public keys). Public keys are not secrets. One extra hit
  in the (now-removed) `_archive/.../qr-verify.ts` was a `did:key:` **placeholder** (an obviously-fake public key).
- **No private key material anywhere, tree or history:** no `*.secret`/`*.key`/`*.pem`/keystore file was ever added
  (`git log --all --diff-filter=A` clean); no committed `"seed"` value (the only `seed` is `registrar.rs` *code* that
  writes the runtime-only, gitignored `registrar.secret`); no `BEGIN … PRIVATE KEY` block in any commit.
- **No real personal data:** commit author is the placeholder `AINRA <dev@ainra.local>`; no real email in content
  (only a `you@company.com` form placeholder). No internal hostnames.
- **Remediation:** add `.gitleaks.toml` allowlisting the vector public-key fields so CI runs gitleaks clean and any
  *new, real* secret still trips it. (This is a documentation/config fix, not a blocker.)

## 2. Private strategy material in history — BLOCKER ❌ (owner decision required)

Two documents that **label themselves PRIVATE** are committed and would become public:

| File | Lines | Self-label | Real third-party company names |
|---|---|---|---|
| `docs/AINRA_Master_Plan_v1.md` | 217 | *"PRIVATE master document"* — and states verbatim: *"third-party names appear here (private doc) but NEVER in public materials"* | ~35 real companies (payment networks, bot-management vendors, enterprise IdPs, CAs, credit bureaus, agent-platform startups) named as targets/foils — enumerated only in the private doc, deliberately NOT repeated here |
| `docs/AINRA_Launch_Readiness_Plan.md` | 74 | *"Private · Slots under Master Plan Parts E–F"* | present |
| `docs/PLAN.md` | 134 | self-described *merge of "Master Plan (strategy/company/GTM)" + "Launch Readiness (tactics)"* — a strategy-execution doc with a GTM "Strategy track" column + kill-gate quotas | no company names, but GTM-tactical; **relocated** (public engineering story lives in STATUS.md + PLAN-M*.md + DOD + GENESIS-CHECKLIST) |

**MTS kept, lightly scrubbed.** `docs/AINRA_Master_Technical_Specification_v1.md` is cited by all the code (`MTS §…`), names only technologies/standards (no commercial brands), so it stays — with its internal framing removed: header "Internal engineering document" → "Engineering companion specification"; `Campaign §`/field-sweep provenance → "July-2026 field research"; two Risk-Register rows de-GTM'd (K-gate dates → generic triggers). The public normative doc remains `AINRA_I_The_Standard.md` (README-linked).

- **Added in commit `eb76283`** (`docs: specs, plans M1-M9, DECISIONS …`). Deleting them from the tree now does **not**
  remove them from the public history — a rewrite is required.
- Publishing these would violate the owner's own stated provenance rule and expose GTM strategy naming ~35 companies.
- The **public-intended** docs are clean: the MTS (`AINRA_Master_Technical_Specification_v1.md`, cited by all the code),
  `AINRA_I_The_Standard.md` (README links it as "the public standard"), all `PLAN-M*.md`, `DECISIONS.md`, `DOD.md`,
  `STATUS.md`, `GENESIS-CHECKLIST.md`, and **all code / kits / tools / front-door** carry **no** company names (verified
  with a word-boundary scan; the only `s7-denylist.txt` hits are the denylist entries themselves).

## 3. Legacy archive in history — BLOCKER ❌ (owner decision required)

- **`_archive/v0-node-prototype/`** — 114 files, ~14 MiB of the pack (dominates repo size), the superseded v0 Node
  prototype: strategy docs, raw research findings, passport SVGs. **210 third-party-company-name hits.**
- **Added in commit `eb146b9`** (`chore(archive): legacy v0 Node prototype …`). Referenced only by one prose line in
  `docs/PLAN.md` (`../_archive/v0-node-prototype/ … see LEGACY.md`).
- It is old, unpublishable (third-party names, private research), and bloat. Removal also requires a history rewrite.

---

## Remediation options for §2 + §3 (ONE-WAY — pick before Task 2)

No remote is configured (never pushed), so a history rewrite is **safe and trivial** — no force-push, no divergence.

- **Option A — Surgical history rewrite (RECOMMENDED).** `git filter-repo --path`-excise the two private docs +
  `_archive/**` from all 24 commits. **Keeps** the milestone-mapped commit structure/messages (the reviewable M1–M10
  history), removes all private material. Commit SHAs change (fine — no remote; DECISIONS references milestones/paths,
  not SHAs). Then scrub the one stray `docs/PLAN.md` line and re-run the full clone acceptance.
- **Option B — Squash to a single "initial public release" commit** from the cleaned tree. Simplest and safest to
  reason about; **loses** the milestone commit granularity.
- **Option C — Two-repo split.** Keep this full-history repo PRIVATE (internal), create a NEW public repo from the
  cleaned tree (Option A or B history). Preserves everything privately; public gets only clean history. More overhead.

**Sub-decision (content):** relocate the two private docs + the archive to the parent Solvatron workspace (kept
private, outside this repo) vs. delete them outright. Recommendation: **relocate** (they retain value to you privately).

**CHOSEN & EXECUTED: Option A + relocate.** Keeps the honest, reviewable milestone history, fully removes private
material, safe because nothing was pushed. The four paths above were copied to `../ainra-private/` and excised from
all commits with `git filter-repo --invert-paths`. Post-rewrite verification (fresh clone: `make preflight` green;
`git log`/`git cat-file` show no trace of the paths; brand scan clean) is recorded in the M10 close-out. Decision
logged as **D-025** in `DECISIONS.md`.
