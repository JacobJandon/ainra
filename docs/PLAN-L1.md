<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# L1 — the launch session (supervised execution of the human buttons)

Not a milestone: no features. The agent prepares and verifies; privileged actions run under the owner's
MASTER GO (full autonomy, park-don't-stall). Prime directives bind: nothing fake · full-output checks ·
no third-party names · zero telemetry · the DoD table untouched — publishing code moves NO DoD row.

## Recorded decisions (owner, verbatim)

> - Git identity stays AINRA <dev@ainra.local>.
> - Signing key stays passphrase-less; I've read your disclosure and accept it.
>   This paragraph is my standing Phase-1 authorization.

MASTER GO scope: "L1 full autonomy. Do everything yourself. Minimize my involvement to zero where physics
allows; where an identity proof is unavoidable, ask me once, and if I don't respond in-session, PARK that
phase and continue with the rest. Never stall the whole session on one credential."

Also owner-directed this session (pre-Phase-1): the landing's questions device + answer moved from the hero
into `#why`, merged with the three beats (commit `24626af`); private release-signing key relocated to
`~/Desktop/ainra-secrets/` (repo keeps only the public half + a pointer).

## Session log

| Phase | State | Evidence |
|---|---|---|
| 0 — preconditions | DONE | tree clean @ 5e61697 · pins v0.2.0→5ae1b12, v0.3.0→af3c869 vs RELEASING.md ✓ · boards committed ✓ · changelog-board-check green ✓ · SSH signing configured + throwaway sign/verify/delete PASS |
| 1 — tags | DONE | `git verify-tag`: Good signature (ED25519 SHA256:xMs+…9Us) for BOTH v0.2.0 + v0.3.0 · tag commits == pins exactly · board files present in tagged commits |
| 2 — public repo | DONE | pre-push checklist ALL GREEN (license ✓ · S7 3-line ✓ · full-history gitleaks "no leaks found" after allowlisting verified-public material: 6× 32-byte Ed25519 public keys in historical site data + 2× public-key fingerprints; negative control: planted secret still trips · PII sweep clean · local paths neutralized at tip, tagged blobs untouched — history never rewritten · README==STATUS==DOD lockstep) · repo created via gh: **https://github.com/JacobJandon/ainra** · branch renamed master→main pre-consumers · main + both signed tags pushed, remote derefs == pins |
| 2 — Stranger Test | see docs/releases/ + closing block | pristine rust:1.96 container, zero credentials, anonymous https clone of the public URL; full board run — see the closing evidence block |
| 3 — npm / PyPI | PARKED (no credentials in-session) | dry-runs GREEN: @ainra/sdk@0.3.0 + @ainra/middleware@0.3.0 `npm pack` verified (dist-only); Python ainra-0.3.0 wheel+sdist `twine check PASSED`. Owner asked once for npm login/OTP + PyPI token; resume commands in the closing block. Note: owner's MASTER GO supersedes RELEASING.md's agent-never-publishes default for this session |
| 4 — truth propagation | DONE | commit 23d7a06 pushed: `<owner>`→JacobJandon in 6 functional files (descriptive docs stay generic) · source links in all footers + llms.txt · ONE documented external-anchor exception in link-check (the canonical repo URL; zero-external-requests guarantee is about loaded resources) · site-check + link-check + S7 green · Desktop bundle rebuilt @ 23d7a06 + LAUNCH.txt stamped with the public URL |
| 5 — outreach/ready/ | DONE (files only, NOTHING sent) | 3 real challenges minted against a live registrar (answer keys ONLY in gitignored ops-verifier/ + ~/Desktop/ainra-secrets/verifier-answer-keys/; leak-check clean ×3) · per-party ONE-PAGER + EMAIL-DRAFT with real public URLs, conformance-afternoon featured · custodian INVITATION + witness NOTE · SOAK-REALITY-CHECK (clock NOT started) · folder deliberately untracked |
| 6 — close | closing block pasted in-session | |

Standing prohibitions: no pushed-history rewrites · no DoD row moves · no announcements · no soak clock ·
no Meridian.
