# M31 — closing the M30b findings, including the one that stays open

M30b ended with eight findings recorded as **confirmed open, not fixed**, and the honest note that "these are real
and need a decision rather than a patch." This milestone makes those decisions. Seven are closed; one is closed as
a *documented, gated divergence* rather than a fix, and saying which is which is the point of this file.

The most serious finding — the proof-of-possession not being bound to its credential — was described in M30b as
"fix is breaking, which is why it is a decision, and it should be made before anyone depends on the current
shape." Nothing external depends on it: the SDKs are unpublished and the external-evidence rows are still zero.
The cost of this change only rises from here, so it was made now rather than handed to someone else.

## What was closed

| M30b finding | Decision | How it is now pinned |
|---|---|---|
| PoP not bound to the credential it accompanies | **D-049** | core unit test + `instance-pop-other-credential-*` (24 vectors, four implementations) + 3 policy-parity rows |
| PoP window is 61 s and presenter-positionable | **D-050** | `POP_MAX_SKEW_SECS` (age) and `POP_MAX_FUTURE_SECS` (skew) separated in all four |
| `verify_wire` still `pub`, still read the wire audience, under a false doc comment | **D-051** | audience is now a parameter; `make engine-parity` |
| `site/verify.html` runs two engines that disagree | **D-051** | `make engine-parity`, in preflight |
| Python's chain-expiry rule inverted vs Rust/TS (fail-open) | **D-052** | `chain-hop-outlived-by-passport-*` (24 vectors) |
| `iid` unbounded and echoed into the log pre-verdict | **D-053** | `MAX_IID_LEN`; `instance-iid-too-long-*` |
| Unbounded capability arrays as an O(n×m) amplifier | **D-053** | `MAX_CAPABILITIES`; `instance-caps-too-many-*` |

## What is NOT closed, and why

**D-054 — non-canonical integer syntax.** `"exp": 2.6e3` gets **VALID** from `ainra-core` and the TS SDK and
**invalid** from Python. A verdict divergence, and worse than M30b recorded it (that note had core as the strict
one; it is not).

It is not closed because every implementation decodes a *parsed object* — by the time the code runs, `2.6e3` is
indistinguishable from `2600`. Closing it means both SDKs must consume bytes and lex numbers themselves. That is an
API change to two published-shape surfaces, in exchange for closing a divergence that grants no privilege: mutating
any signed field breaks its signature, and the exponent spelling that survives denotes the identical value.

`make number-syntax` pins the measured behaviour of each implementation so the divergence cannot widen, narrow, or
be quietly "fixed" in one place. Python's reason was corrected to `schema_violation` — the one part that was cheap
and unambiguously better.

## Corrections to what M30b recorded

Two of the eight notes were wrong in detail, found by verifying each before acting rather than trusting the record:

- The chain-expiry note said a hop expiring before the passport was "accepted by Python and refused by Rust and TS",
  attributing it to a stricter rule. The rules are **inverted**, not merely different — Rust/TS seed from the first
  hop, Python seeded from the passport — which is why no equality-valued vector could see it.
- The malleability note called it "a real three-way divergence in reason". It is a divergence in **verdict**, and
  the implementation it named as strict is one of the two permissive ones.

## Also fixed along the way

- `cmdInstancePresent` in the CLI had the credential's *path* but never loaded it — caught by `make skills-replay`,
  not by review.
- `b64e` in the Python verifier was imported inside a function two hundred lines below the new call site; the module
  imported fine and would have raised `NameError` at runtime.
- `decodeInstance` is now exported from the TS SDK. D-049 makes the minting API take a decoded credential, and a
  container receives JSON — without the export it would have had to hand-roll base64url, which D-029 places in
  exactly one gateway.
- `docs/SETTLERS.md` still listed **R1** (build the instance rung) as open. It shipped in M28. R6's text cited site
  wording changed in the same milestone.
- The claims registry exempted `PLAN-M29.md` by name; it now exempts completed milestone plans as a class, which is
  the category they belong to alongside release boards.

## Negative controls run for this milestone

Every one reddened, and each is named with what it proves:

1. Delete `cred` from the core PoP body → the substitution test fails, and is the **only** failure.
2. Restore Python's inverted chain rule → 24 differential mismatches, `core=chain_expired` vs `py=valid`.
3. Raise `MAX_IID_LEN` to 4096 → exactly 24 vectors fail, `expected schema_violation, got Valid`.
4. Restore either half of the old browser wiring → every `engine-parity` row flips to DIFFER.
5. Drop the Python PoP audience guard → `pop.audience_mismatch_refused` goes `sdk-ts=refused sdk-py=minted`.
6. The parity harness's own positive control (`pop.wellformed_is_produced`) failed on first run and was right to:
   TS takes a decoded credential and Python takes the wire dict, an asymmetry the harness was hiding.

## Vectors

1009 → 1105. Four new families, 96 vectors, each carrying an attack or a bound rather than a variation:
`instance-pop-other-credential`, `instance-iid-too-long`, `instance-caps-too-many`,
`chain-hop-outlived-by-passport`. The 216 pre-existing instance vectors were regenerated because D-049 changes the
signed bytes — a deliberate format change, and the regeneration was audited: **exactly** the instance family moved
and nothing else.
