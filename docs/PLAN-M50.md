<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M50 — No known fail-open path, no stale claim, and a board that can count strangers

Written on 3 November 2026, after 0.6.0 shipped. PLAN-M47, M48 and M49 are done, so this plan comes from the
repository itself: five independent surveys (roadmap and definition of done, decisions, deprecations and security
notes, the code, and the public honest status) reported 129 open items, merged into 47. This plan takes the ones that
need nobody outside the project and no undecided one-way door. The rest are listed at the end, each with its owner.

## Before M50: the release manifest's order

`tools/repro.sh` sorted the reproducibility manifest by the machine's locale, so a manifest written on a workstation
never matched CI's container (every hash identical, the lines in another order). `make release` refused in CI for
v0.4.0 through v0.6.0, and those releases have no attached artifacts. `LC_ALL=C` in `tools/repro.sh` and
`scripts/release.sh`, and the manifest re-sorted. Re-attaching signed artifacts to the existing pages stays with the
maintainer, who holds the key.

## The steps

**1. Directory rollback is refused (the fail-open fix).** *Done 2026-11-03 (D-083).* `Directory.epoch` exists so a verifier can refuse an older
signed directory — one that still lists a de-accredited registrar or omits a revoked delegate — but no verifier does.
An optional floor (`min_epoch` / `minEpoch`) on directory acceptance in the Rust core, the TypeScript and Python SDKs
and the edge gate; a directory below it is refused (`directory_rollback`). Long-lived holders (middleware, edge gate,
the hosted verifier) keep the highest epoch they accepted and pass it on refresh; a restart starts from the configured
floor, and the docs say so. A new corpus `vectors/v1-directory-epoch/` (equal accepts, lower refuses, no floor accepts)
in `make diff` across all implementations. WITNESS: drop the comparison in any one implementation and the vector goes
red; a middleware test that sees epoch 2 and then epoch 1 must refuse the second. The floor stays optional: making it
mandatory would break the API.

**2. A short status list is a corpus vector.** *Done 2026-11-03 (`g28`, `g29`).* A status list that declares `bit_len` N and carries fewer bytes must be
refused. Today only one Python unit test pins it. A gate vector in `vectors/v1-gate`, held by every implementation.
WITNESS: remove the length guard in any one implementation (the M30b shape) and the vector goes red.

**3. Conformance contract v2.** *Done 2026-11-03 (D-084).* The third-party contract (`tools/conformance`, `CONTRACT.md`) covers passports, deltas
and directories only; the gate, presentation, link, decision and directory-epoch corpora are outside it, which is where
D-072, D-074 and D-075 lived. Additive kinds, `report_version: "2"`, and a `profile` of `core` (the v1 kinds, still
valid) or `full`. WITNESS: an adapter that skips status authentication — the D-072 shape — passes `core` and must fail
`full`.

**4. The probe follows a renewal (D-055).** *Done 2026-11-03 (P6).* The probe kit issues and revokes, but never renews. Issue, renew twice,
mint an instance credential under an old generation, revoke the lineage: every generation and its instance credentials
must read revoked. WITNESS: a dishonest registrar mode that flips only the newest generation's bit must be caught.

**5. The genesis board counts witnesses and outside rebuilds from evidence.** The witness row is a literal ⏳ that
nothing can turn, and the definition of done's "an outsider rebuilds the root from public artifacts" has no row at
all. Evidence intakes: cosignatures from at least three distinct keys outside the project over a real checkpoint, and
a signed rebuild statement whose manifest digest matches. WITNESS: three cosignatures from one key, or from a project
key, must leave the row ⏳ ("never a fake ✅"). The wording stays "independent cosignatures observed", never "quorum
constituted".

**6. The honesty sweep, and a gate so the drift cannot return.** ROADMAP still says "Unreleased (0.5.0)"; STATUS,
CHANGELOG, RELEASING, PUBLISHING, SECURITY and two READMEs describe states that are over; drill counts disagree;
`site/status.md` garbles a heading because `tools/site-mirrors.mjs` decodes `&lt;` before its last tag strip. Correct
each, with dated amendments in DECISIONS rather than silent edits. Then a gate: a tagged version may not be called
unreleased anywhere, the drill count must agree everywhere, and a mirror must keep every heading's text. WITNESS: a
fixture with a tagged version still called unreleased, and one with `&lt;` in a heading, must each go red. The
regenerated site mirror is committed; deploying it is the owner's step.

**7. Deno and Bun run in CI, with no SKIP.** The edge gate is tested in Node and workerd; Deno and Bun are skipped and
the run stays green. Pinned runtimes and SHA-pinned setup actions; `REQUIRE_ALL_RUNTIMES=1` turns a missing runtime
red. WITNESS: with Bun off the path and the flag set, the target fails. Run from a clean clone in the CI image before
pushing.

## Done means

`make preflight`, `make diff`, `make conformance` (full), `make live-drills` and `make genesis-status` green from a clean
clone, and each step's negative control shown red once, before it is called done.

## Next, ranked (not in M50)

1. Currency mode (D-021) in Python and the edge gate — it exists in TypeScript only.
2. Move in-repo consumers to `@ainra/sdk/conformance` / `ainra.conformance`, so the 0.7.0 removal is one line.
3. A1 issuance requires a checked principal proof in the reference registrar's policy.
4. Clear the negative-control debt (15 gates without a named witness) and widen the S7 scan to shipped packages.
5. Coverage-guided fuzz targets for the newer parsers (link, decision and head receipt, presentation), and one recorded
   soak run.

## Not code

Owner: re-attach signed release artifacts; submit the Internet-Draft (the Datatracker reopens after 14 November);
the MCP registry namespace; publishing `@ainra/edge`; a GitHub organisation; hosting the online verifier and a public
demo registrar; the D-077 fee ruling; the legal form; site copy for Link. The outside world: a first design partner,
then the recorded ceremony; three independent verifiers; the 14-day, three-region soak; at least three witness
operators; a third-party rebuild; a second registrar; an external audit.
