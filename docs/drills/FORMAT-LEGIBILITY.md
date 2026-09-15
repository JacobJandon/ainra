<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — can the format be recovered from paper?

**Question.** Could someone with no AINRA code parse a passport, check that it is in the log, and see whether it is
revoked — working only from [WIRE-FORMAT-PRIMER.md](../WIRE-FORMAT-PRIMER.md)?

**Method.** `tools/legibility-drill.mjs` implements a parser from the primer's prose alone. It imports **nothing**
from this repository — only `node:crypto`, `node:zlib` and `node:fs`. Every constant in it (the `0x00`/`0x01`
prefixes, LSB-first bit order, the leaf-minus-`log` rule, the freshness bounds) is transcribed from the document,
not from our source. The drill therefore tests the **document**: if the primer is wrong or incomplete, this fails.

**Run.** 2026-09-15T14:21:57.883Z · 80 vectors from the published corpus.

| Check | Result |
|---|---|
| valid vectors — leaf, inclusion proof, window, status, Ed25519 | 40/40 |
| revoked vectors read as revoked by the bit rule | 20/20 |
| not-logged vectors rejected by the proof | 20/20 |
| control — one edited claim breaks the leaf and the proof | ✓ |
| control — the edited claim fails Ed25519 | ✓ |
| control — an out-of-range status index reads as **revoked** | ✓ |

**Verdict: the wire format is recoverable from the primer alone.**

## The honest limit

The parser checks Ed25519 and **not** ML-DSA-65: the post-quantum half needs an implementation no standard library
carries. That is stated in the primer's §9 as well, and it is the correct reporting posture — a reader who can
check only one of the two signatures has performed **partial verification** and must say so, never "valid".

Everything else is fully recoverable: structure, canonical JSON, the validity window, the RFC 6962 leaf and
inclusion proof, and the revocation bit including its fail-closed out-of-range rule.
