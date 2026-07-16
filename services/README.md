<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# services/ — the M2 transparency pipeline

`ainra-services` is the M2 reference implementation of the transparency pipeline, **thin over `ainra-core`** — every
consensus-critical primitive (RFC 6962 inclusion + consistency, hybrid + SLH-DSA signing, the ADR-002 delegate
signer) lives in the audited core; these daemons only persist, sequence, and serve. There is no novel security
logic here (MTS ADR-010's reuse-only rule).

| Binary / module | Role | Spec |
|---|---|---|
| `logd` | Persistent append-only RFC 6962 log: fsync'd entries, ADR-002 delegate-signed checkpoints, inclusion + **consistency** proofs. | MTS §13/§14, C2 |
| `witnessd` | Independent consistency cosigner: cosigns append-only growth, **refuses + alarms on a fork** (equivocation or history rewrite). | MTS §12, C3 |
| `statusd` | Token Status List publisher: signed list + `issued_at`, fail-closed freshness on the verifier side. | MTS §16, C4 |
| `pipeline-demo` | Runs all three in-process end to end, printing a narrative (`make drill`). | — |

**Run it:**
```sh
make drill                                   # the whole pipeline + an injected-fork drill, in-process
cargo test -p ainra-services                 # the fork drill + persistence + status tests, asserted
cargo run -p ainra-services --bin logd       # HTTP daemon on 127.0.0.1:4881 (also statusd :4882, witnessd :4883)
```

The marquee test (`tests/fork_drill.rs`) is the M2/M8 DoD property in miniature: an honestly-growing log is cosigned
via real consistency proofs; an equivocating fork **cannot** produce a valid consistency proof, so the witness
catches it — *not us*. Local only (127.0.0.1), zero telemetry, no outbound calls.

## Production note (DECISIONS D-011)

`logd` stores entries as an fsync'd append-only file and rebuilds the Merkle tree via `ainra_core::merkle`. The
**production** `logd` swaps that file store for **Tessera**'s tiles; the proofs are byte-identical because the tree
math is the same core code — Tessera changes *storage*, not *semantics*. FROST-threshold witnessing and the
witness-network onboarding are later milestones (M4/M6); `witnessd` here is a single-key stand-in whose
verification is identical (RFC 8032 signatures).
