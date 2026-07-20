<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- TEMPLATE — rendered by `make declaration` (tools/declaration.mjs) ONLY when every {{claim}} resolves to a real
     artifact. Never publish this template; publish the rendered founding-declaration.md, which cannot exist unless
     the evidence does. Each {{CLAIM}} maps to an evidence artifact; a missing one is a loud TODO + a nonzero exit. -->

# The founding of AINRA — {{GENESIS_DATE}}

AINRA — the neutral root of AI-agent identity — has a root. It was born in the open, on the record, and everything
below resolves to an artifact anyone can check. We claim nothing we cannot show.

## The ceremony

On {{GENESIS_DATE}} a **5-of-9 threshold ceremony** minted the AINRA root — FROST-Ed25519 with an SLH-DSA hash-based
component (ADR-001), across custodians in **{{JURISDICTIONS}} jurisdictions**, recorded end to end.

- **Transcript hash:** `{{TRANSCRIPT_SHA256}}`
- **Published to:** {{TRANSCRIPT_MIRRORS}}
- **Recording:** {{RECORDING_REF}}
- Recompute it yourself: `make verify-transcript TRANSCRIPT=<mirror-url> SHA256={{TRANSCRIPT_SHA256}}`

## Independently verified

**{{VERIFIER_COUNT}} external verifiers**, on their own machines, ran the published `@ainra/sdk` against a fresh
unpublishable challenge and produced execution-bound attestations we accepted without trusting them — distinct by
public key. The root can be dark; their green was their own.

## Witnessed

**{{WITNESS_COUNT}} independent witnesses**, operated by parties we do not control, cosigned the first production log
checkpoints. A fork cannot reach their quorum.

## Soaked

A **{{SOAK_DAYS}}-day soak across {{SOAK_REGIONS}} regions** measured revocation propagation: **p95 = {{SOAK_P95}}s**
(target < 60 s), in a signed, tamper-evident report.

## The board

`make genesis-status` reads **{{BOARD}}** — every green backed by a signature-checked artifact, nothing asserted.

---

*The root exists. Whether the world uses it is earned, not declared. Everything here is checkable; if any line ever
disagrees with the artifacts, the artifacts win.*
