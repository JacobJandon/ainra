<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# samples/ — the agent passport, as a book

Open **[index.html](index.html)** for the showcase: one specimen credential shown as a three-face book (cover ·
data page · endorsements&log), rendered in the v12 design (`../docs/DESIGN.md`). It's the "hold it in your hand"
artifact. For the interactive version — tamper switches, live verdicts — run `make console`.

The hero specimen is a **delegated** agent (`ainra:registrar-07:acme:support-bot@1.0.0`): it received its
authority through a real two-hop, dual-signed, logged delegation chain, so the endorsements page tells the whole
story. All three kinds (`valid`, `delegated`, `revoked`) are rendered as `passport-<kind>-<cover|data|stamps>.svg`
and back the live console.

## What's real vs. illustrative

**Real, for every sample (M2):** Ed25519 + ML-DSA-65 hybrid signing; an SLH-DSA-signed checkpoint; RFC 6962 log
inclusion for the credential AND for every delegation hop; **dual-signed** hops (delegator + delegatee); and the
verdict shown is produced by actually calling `ainra_core::verify::verify` — never hand-written (see
`../crates/ainra-core/examples/sample_passport.rs`). The passport-photo **data glyph** and the fingerprint derive
from the real credential.

### The data glyph (the passport photo)

The 7×7 dot grid where a passport photo would go is not decoration — it **encodes the record**, one fact per row,
so a reader with the legend can decode the passport by eye (and any change to the data changes the picture):

| Row | Encodes | Read as |
|---|---|---|
| **T** | Tier (L0–L4) | green bar, `L0`→1 cell … `L4`→5 cells |
| **A** | Authority class (A1–A4) | ink bar, `A2`→2 cells |
| **C** | Capabilities granted | green bar, one cell per capability |
| **H** | Delegable headroom (`scope_ceiling − capabilities`) | ink bar, slack still narrowable downstream |
| **S** | Status | full **green** row = VALID, full **red** row = REVOKED |
| **K·K** | Key fingerprint | 14 true bits of `SHA-256(holder Ed25519 pubkey)` — a faithful visual fingerprint |

The caption prints the decode (`L3 · A2 · 2CAP · VALID`) in green, or red on a revoked credential.

**Illustrative by design (a sample needs readable data):** the business field values — dates, capability names,
lineage/operator strings. S7-safe placeholders (`registrar-07`, `acme`) and a chosen one-year window.

## Reproduce

```sh
cd ..                                   # ainra/
make samples                            # regenerate the 3 signed specimens + render all book faces
node tools/render-samples.mjs           # (render only)
```

`samples/data/*.json` carries the full presentation (claims, both signatures, chain-party keys, hop proofs, the
checkpoint, inclusion proofs) — anyone can independently re-verify a sample through `ainra-core` or
`packages/sdk-ts`; that is exactly what the example does to produce the `verdict` field.
