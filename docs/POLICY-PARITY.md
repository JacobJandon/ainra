<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Policy parity — who decides, and what a default trusts

The conformance corpus proves the implementations agree on **verdicts over wire data**. It cannot prove they agree
on **who supplies a value**, **what a default constructor trusts**, or **what happens when a caller omits an
argument** — and two implementations can pass all 1153 vectors while disagreeing completely about those.

That gap is not theoretical. It has produced four defects:

| when | defect | why the corpus could not catch it |
|---|---|---|
| M28→M29 | `sdk-py` took the **audience** off the presentation bundle instead of the verifier's own identity | vectors pin the audience as an input, exactly as they pin `now` |
| M30 | `sdk-py` let the **presenter choose the freshness class** — an hour-stale status accepted at `F3` | same: the class is a pinned input on the wire |
| M30 | `sdk-py` **required `act_chain`** where `ainra-core` marks it `#[serde(default)]` | the generator always emits the field, so the omitted case never reaches the corpus |
| M42 | the **Rust gate path** (`@ainra/edge`, `ainra verify-request`) took the **status list and its issue time from the presenter** and never checked the registrar's signature over them — a revoked agent could present its old list re-dated to now and be let in (D-072) | a vector's status is a fixture input with no signature; and the Rust path was not a column of this harness |

`make policy-parity` runs each decision below against every implementation, called the way an integrator would —
**including the wrong ways** — and requires the same closed outcome with the same named reason.

## The decisions

| decision | correct behaviour | rationale | covered |
|---|---|---|---|
| **who supplies the audience** | the VERIFIER's own, never the bundle's. Default `""` refuses every instance credential | a presenter naming its own audience defeats audience binding entirely; a service that has not said who it is cannot be the intended recipient of anything | sdk-ts · sdk-py |
| **who chooses the freshness class** | the VERIFIER's own (default `F2`), never the bundle's | the class bounds how long a genuine but **superseded** status snapshot stays usable — letting the presenter choose lets a holder of a pre-revocation snapshot stretch revocation from 30 s to 24 h | sdk-ts · sdk-py |
| **who supplies the mandate-revocation set** | the verifier's, empty in GA (no dynamic feed) | a presenter must not be able to drop a revocation | sdk-ts · sdk-py |
| **who supplies the revoked-delegate set** | the trusted directory, never the bundle | same reason | sdk-ts · sdk-py |
| **who signs the status** | the REGISTRAR, under the status key the signed directory publishes. A list, a length, an issue time or a URI the signature does not cover is `stale_status` | the status list is the revocation; taken on the presenter's word, revocation is optional | sdk-ts · sdk-py · core-gate |
| **who supplies `now`** | the caller, always | freshness and expiry are the receiving side's policy | all |
| **what a default constructor trusts** | nothing that grants access. Defaults must fail closed | a default that accepts is a default that ships | sdk-ts · sdk-py |
| **omitted parameters** | fail closed with the correct named reason, identically everywhere | a debugging integrator must land on the right layer in every language | sdk-ts · sdk-py |

## Known asymmetries — recorded rather than smoothed over

These are real differences between the implementations. They are written down because the alternative is testing
only what both happen to support, which is how the divergences above survived.

- **Directory authentication at construction.** `Verifier.fromDirectory` (TS) **requires** a root-signed directory
  and returns `null` if it does not verify. Python's `Verifier(anchors, …)` accepts **raw anchors** with no
  directory authentication, so a Python integrator can build a verifier over anchors nobody signed. Python's
  `from_directory` does authenticate; the raw constructor is the loose door.
- **Currency mode (D-021).** TS has it (fresh-head binding + monotonic sequence, closing genuine-snapshot replay
  to sub-window). Python has no equivalent, so a Python integrator cannot obtain that protection.
- **`ainra-core` (Rust) has no defaults to get wrong — and that is not the same as its gate path having none.**
  `Presentation` is a struct literal: every field must be supplied by name, so omitting one is a **compile error**,
  not a silently permissive default. That is why the core itself is not a row. But a struct that must be filled in
  says nothing about WHERE each value comes from, and the code that fills it for a gate — `ainra-adapter`, reached
  by `@ainra/edge` and `ainra verify-request` — filled the status list and its issue time from the wire. This
  paragraph used to end at "the Rust core is not a row in the harness", and the Rust gate path was therefore
  compared with nothing (D-072). It is now the `core-gate` column: driven through `ainra verify-request`, on every
  row that a signed directory can express. The SDK-constructor and minting rows do not apply to it.

## What the differential covers, and what it structurally cannot

> **The conformance corpus proves that every implementation reaches the same verdict, with the same named reason,
> on the same bytes. It cannot prove they agree about who supplies a value, what a default trusts, or what happens
> when a caller omits an argument — that is API shape and default policy, and it is what `make policy-parity`
> covers.**

That sentence is also in `CONTRIBUTING.md`, and `make diff` prints it at the end of its own report, so nobody
reads a green differential as a broader guarantee than it is.

## Adding a decision

1. Add the scenario to `tools/policy-parity.mjs` — including the way a caller gets it **wrong**.
2. Run it. If an implementation disagrees, that is a finding, not a test to adjust.
3. Regenerate nothing: this file is hand-maintained prose about intent, and the harness is the executable half.
