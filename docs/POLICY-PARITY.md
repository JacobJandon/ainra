<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Policy parity — who decides, and what a default trusts

The conformance corpus proves the implementations agree on **verdicts over wire data**. It cannot prove they agree
on **who supplies a value**, **what a default constructor trusts**, or **what happens when a caller omits an
argument** — and two implementations can pass all 1009 vectors while disagreeing completely about those.

That gap is not theoretical. It has produced three defects:

| when | defect | why the corpus could not catch it |
|---|---|---|
| M28→M29 | `sdk-py` took the **audience** off the presentation bundle instead of the verifier's own identity | vectors pin the audience as an input, exactly as they pin `now` |
| M30 | `sdk-py` let the **presenter choose the freshness class** — an hour-stale status accepted at `F3` | same: the class is a pinned input on the wire |
| M30 | `sdk-py` **required `act_chain`** where `ainra-core` marks it `#[serde(default)]` | the generator always emits the field, so the omitted case never reaches the corpus |

`make policy-parity` runs each decision below against every implementation, called the way an integrator would —
**including the wrong ways** — and requires the same closed outcome with the same named reason.

## The decisions

| decision | correct behaviour | rationale | covered |
|---|---|---|---|
| **who supplies the audience** | the VERIFIER's own, never the bundle's. Default `""` refuses every instance credential | a presenter naming its own audience defeats audience binding entirely; a service that has not said who it is cannot be the intended recipient of anything | sdk-ts · sdk-py |
| **who chooses the freshness class** | the VERIFIER's own (default `F2`), never the bundle's | the class bounds how long a genuine but **superseded** status snapshot stays usable — letting the presenter choose lets a holder of a pre-revocation snapshot stretch revocation from 30 s to 24 h | sdk-ts · sdk-py |
| **who supplies the mandate-revocation set** | the verifier's, empty in GA (no dynamic feed) | a presenter must not be able to drop a revocation | sdk-ts · sdk-py |
| **who supplies the revoked-delegate set** | the trusted directory, never the bundle | same reason | sdk-ts · sdk-py |
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
- **`ainra-core` (Rust) has no defaults to get wrong.** `Presentation` is a struct literal: every field must be
  supplied by name, so omitting one is a **compile error**, not a silently permissive default. This is the
  strongest form of fail-closed in the repository and it is why the Rust core is not a row in the harness —
  demonstrated in M28, when adding two fields broke every construction site in the workspace until each was
  updated deliberately.

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
