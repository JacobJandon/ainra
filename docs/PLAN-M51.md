<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M51 — Currency everywhere, one import path, and the debts M50 named

Written on 3 November 2026, when PLAN-M50's seven steps were done. These are M50's ranked "Next" items, in order;
each still needs nobody outside the project and no undecided one-way door.

## The steps

**1. Currency mode in every gate, held to one corpus.** *Done 2026-11-03 (D-086; 18 vectors; reviewed before commit, eleven findings fixed).* D-021's currency mode — the verifier requires a
delegate-signed fresh head, binds it to the presented list, and refuses a lower `seq` than one it has seen — exists
in `@ainra/sdk` only. A Rust gate (`@ainra/edge`, `ainra verify-request`) and the Python package accept a genuine
pre-revocation snapshot for the whole freshness window even after the revocation has been observed. Add it to the
adapter's gate path (state held by the caller), the WASM edge export and `createAinraEdgeGate({ currency })`, and
the Python `Verifier(currency=True)`. A new corpus `vectors/v1-currency`: each vector is one verifier's life, a
sequence of bundles with the expected answer at each step (current valid; replay after the revocation was observed
refused; fresh head stripped, for another list, out of window, under a wrong-scope cert, or for another uri refused;
the passive verifier that never saw the newer head still accepts — the honest limit, pinned). The head binds the
presented list's text, not a re-encoding of it. In `make diff`, the edge tests and conformance `full`. WITNESS: drop
the seq comparison in any one implementation and the replay step goes red.

Found while designing it: the Python package checks neither a fresh head's nor a checkpoint's delegate-cert lifetime
against ADR-002's 92-day ceiling (Rust and TypeScript both do), and no vector has a cert that long. A gate vector with a
checkpoint under an over-long cert, and a currency step with a fresh head under one, close it. And no implementation
refuses a fresh head signed by a delegate the directory revokes, though all refuse its checkpoints; currency mode will.

**2. One import path for replaying vectors.** Move the in-repo consumers (site JS, tools, publish-preflight smoke) to
`@ainra/sdk/conformance` and `ainra.conformance`, so the 0.7.0 removal from the package roots is one line. WITNESS: a
gate that fails when anything in the repository imports a replay function from a package root.

**3. A1 means a checked principal proof.** The reference registrar issues `auth_class: A1` only with a principal
proof a pluggable checker accepts (the personhood kit first); anything else is refused, not downgraded silently.
WITNESS: an A1 request with a junk proof must be refused.

**4. Negative-control debt and the S7 scan.** Name a witness for the gates in `tools/negative-control-baseline.json`,
starting with `s7-lint`, `reasons-check` and `presentation-diff`, so the baseline shrinks; widen the S7 scan to the
shipped packages. WITNESS: each named control shown red once.

**5. Fuzz the newer parsers.** Coverage-guided targets for link (ES256K), decision and head receipts, RFC 9421
presentations, directories and deltas; one recorded soak run.

## Done means

`make preflight`, `make diff`, `make conformance` and `make live-drills` green from a clean clone, each step's
negative control shown red once.
