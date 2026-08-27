<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — root-dark verification from a mirror

**Question.** With every AINRA-operated service unreachable, does an already-issued credential still verify using
only bytes a mirror serves?

**Method.** Copy the published mirror into an isolated cage outside the repository, then verify using **only** files
inside it. The isolation is the method: a drill run inside the repository would pass while proving nothing, because
every missing artifact is one directory away. No network is used at any point.

**Run.** 2026-08-27T11:46:46.626Z

| Step | Result |
|---|---|
| conformance vector verifies from mirror bytes | ✓ |
| issued credential verifies from mirror bytes | ✓ |

**Verdict: root-dark verification works from mirror bytes alone**, for both a conformance vector and an issued credential.

- A conformance vector carries its own `anchors`, so it needs no other file. This is the claim the project could always make.
- Verification used the published directory and the two root public keys only — the shape a stranger's verifier is built in, holding no secret. A revoked bundle checked against the same anchors is refused (`revoked`), so "valid" above is a decision rather than a default.

## The minimum artifact set a mirror must carry

Measured from the mirror itself, not asserted:

| Group | Files | Size |
|---|---|---|
| `vectors` | 1182 | 32.6 MB |
| `samples` | 16 | 0.2 MB |
| `MANIFEST.sha256` | 1 | 0.1 MB |
| `kits` | 5 | 0.1 MB |
| **total** | **1204** | **33.0 MB** |

**What this drill does not cover.** It proves the bytes are sufficient and present. It does not prove any
particular host serves them, nor that a mirror stays current — that is the staleness horizon's job
([STALENESS.md](../STALENESS.md)).
