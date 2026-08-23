<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M30 — the instance layer red-teamed, and the class the corpus cannot reach

ADR-019 shipped a new credential layer with 216 vectors and no adversarial pass. Every other cryptographic surface
in this repository went through one before it was trusted, and that process is what caught the revocation bypass,
the quorum forgery, the execution overclaim and the `prev_leaf` decoder differential.

## How the review ran, and where it was interrupted

Four reviewers were dispatched against seven attack dimensions. **One completed** (revocation coupling). **Three
were killed mid-run by a session capacity limit** — proof-of-possession/windows, narrowing/binding, and
encoding/reason-integrity. No further reviewers could be dispatched.

**Stated plainly, as the milestone requires:** those three dimensions were completed by me directly, and the
**refute phase was performed by me rather than by independent reviewers.** Every claim the completed reviewer made
was re-derived from the code and re-demonstrated before any of it was acted on — two of its claims are recorded
below as **confirmed**, and its framing of a third was corrected. That is weaker than an independent refute pass,
and it is written here rather than left to be assumed.

---

## Findings

### REAL · A — a revoked passport verified VALID in the Python SDK (critical)

Two independent holes, both demonstrated end to end on a shipped vector:

```
honest bundle (registrar says REVOKED) -> revoked
status TRUNCATED to zero bytes         -> VALID
status REPLACED with an all-clear map  -> VALID
```

1. **Out-of-range read as "not revoked".** `verify.py` read `else 0` for any index past the delivered bytes, so
   declaring a long `bit_len` and sending a short list bought a free all-clear. `ainra-core` maps every
   out-of-range index to `Revoked` (`status.rs:136-141`) — this was the exact opposite.
2. **The status list was never authenticated.** D-020 — the M5 adversarial finding, closed in the TS wedge at the
   time — was simply never implemented here, so a forged all-clear bitmap was taken at face value.

**Fixed:** a length guard plus `else 1`, and `_authenticate_status` mirroring TS (signed publication required,
triple URI binding, hybrid signature over canonical `{bit_len, issued_at, status_list, uri}`, every failure
`stale_status`). **Pinned:** `packages/sdk-py/tests/test_status_authentication.py`. **Controls:** restoring `else 0`
reddens the truncation test; removing the authentication call reddens the forgery test.

*Why no vector could have caught it:* no vector delivers a list shorter than it declares, and the frozen `verify()`
primitive treats status bits as a **trusted input** by design — authentication belongs in the GA layer.

### REAL · B — `from_directory` silently dropped three fields (high)

`distrust_from_leaf` (D-044), plus `status_ed25519`/`status_mldsa65`/`status_uri`. Every Python verifier built the
documented way therefore treated a **graduated-distrusted registrar as fully trusted**, discarding the root's
published, appealable cutoff — and without the status key, finding A could not be fixed at all. **Fixed and pinned;**
control: dropping the fields again reddens `test_status_key_uri_and_distrust_cutoff_all_survive`.

### REAL · C — the browser let the presenter name its own audience (high)

`verify_bundle_json` had **no audience parameter**, so it read `WirePresentation.audience` — the field that exists
only so the corpus can pin audience cases, exactly as it pins `now`. `ainra-wasm::verify` is a thin wrapper, so
every browser page and embedded Rust verifier accepted an instance credential addressed to somebody else. The doc
comment three lines above read *"A presenter cannot set this."*

**Fixed:** the audience is a parameter (`verify_bundle_json_aud`, `ainra-wasm::verify_aud`); the no-audience form
defaults to the fail-closed empty string. **Pinned:** `crates/ainra-adapter` `audience_tests`. **Control** produces:

```
a foreign audience was accepted: {"status":"valid",…,"instance_iid":"i-0794","instance_exp":2600}
```

### REAL · D — the presenter chose the freshness class in Python (high)

Found by the policy-parity harness, not the reviewers. An hour-stale status was refused at F1 and F2 and **accepted
at F3** because the class came off the bundle. The class bounds how long a genuine but *superseded* snapshot stays
usable, so this stretched the revocation window from 30 s to 24 h. **Fixed** (the verifier owns its class, default
F2, matching TS); **pinned** by `make policy-parity`.

### REAL · E — Python required `act_chain`; the core marks it optional (interop)

`ainra-core` declares `#[serde(default)]` (`passport.rs:141`); Python required it, so it answered
`schema_violation` on a root-issued passport with no delegation — **including the bundle shipped in our own
external verifier kit**. **Fixed and pinned.** The corpus cannot catch it: the generator always emits the field.

### REAL · F — `verify_instance` is public and means nothing alone (low, documentation)

It takes no status list and no checkpoint, so it cannot see revocation or logging; handed a revoked lineage it
returns `Ok(())`. The ADR-019 coupling is **ordinal** — it holds because the nine passport steps run first. The
obvious-looking name invited exactly that misuse. **Fixed:** a `# This function is MEANINGLESS on its own` section
naming the trap. Not sealed to `pub(crate)`: it is legitimately useful to embedders who *do* run the full path.

---

## Dismissed, with the reasoning

- **Instance under a delegated passport could exceed the delegation.** *Non-issue.* Step 6 (`verify.rs:164`) refuses
  unless `p.capabilities ⊆ chain-narrowed effective`, and it runs **before** step 10 passes `p.capabilities`
  (`:255`). So `ic ⊆ p ⊆ eff` transitively. Passing the raw set is safe *because* step 6 already proved it narrow.
- **Delegate revocation above an instance.** *Non-issue.* A revoked delegate cert is `checkpoint_invalid` at step 9,
  ~45 lines before the rung.
- **Non-canonical encoding on the new instance fields.** *Non-issue.* All **seven** base64 fields × three
  mutations (padding, standard alphabet, embedded whitespace) = 21 cases, every one `schema_violation` in both
  implementations. Only one field had a vector; the other six are now known good by test.
- **Reason collapse under simultaneous defects.** *Non-issue.* Five stacked-defect cases produce identical,
  deterministic reasons in both implementations, and binding correctly wins over window
  (`wrong subject + expired → instance_sig_invalid`).
- **Integers near 2^53.** *Non-issue.* Both canonicalisers reject anything outside the JS-safe range —
  `canon.ts:10` and `canon.rs:50-57` — so a value JS could not represent exactly cannot be signed at all.
- **Cross-protocol reuse of a PoP signature.** *Non-issue today, with a caveat worth recording.* The signed
  structures have **disjoint key sets** (`{aud,nonce,ts}` vs `{aud,capabilities,exp,iid,ikey,nbf,passport_leaf,sub}`
  vs the delta and fresh-head bodies), and each key signs exactly one kind of object. Safety therefore rests on
  *disjointness plus single-purpose keys*, **not** on an explicit domain-separation tag. Nothing is exploitable
  today; a future structure sharing a key set would be, and a type tag in the signing bytes would remove the
  question permanently. Recorded as a hardening candidate, not a defect.

## Known limitations, recorded rather than closed

- **Renewal overlap.** Revocation is keyed on the *presented passport's* status index, not the lineage. During an
  ADR-017 renewal overlap two passports share a control key at two indices, so an instance minted under the
  superseded one survives a revocation applied only to the current one. The reference registrar sweeps every live
  and superseded index, so this is closed **operationally** — but not by the verify path, which holds `prev_leaf`
  and never consults it. A third-party registrar revoking only the current index reopens it.
- **PoP replay within the timestamp window** against the same audience, by someone who already has the bundle.
  Documented in ADR-019 from the start; single-use is caller state and core holds none.
- **Coverage gaps** (no vectors today): instance + delegate-mode checkpoint; instance + renewal; a status list
  shorter than its declared `bit_len` (the last is now pinned by a Python test rather than a vector).

---

# The independent re-review (M30b)

The three dimensions lost to the capacity limit were re-run, plus the refute pass that was missing. **The most
serious findings are against my own work, not against ADR-019.** Each was re-derived and re-demonstrated by me
before being acted on.

## Fixed in this pass

| # | finding | severity | pinned by |
|---|---|---|---|
| 1 | **TS type confusion.** TS types are erased at runtime and the decoder checked nothing, so a credential validly minted with `"nbf": "-"` reached the window comparisons as a string. Every relational operator yields `NaN`, and `NaN` comparisons are all false — window, ≤1 h ceiling and PoP freshness **all bypassed at once**: an unbounded bearer token, the exact pre-ADR-019 state. Rust was safe (serde `u64`), Python guards with `isinstance`; TS was alone, and the corpus cannot see it because the generator only emits integers. | **high** | decode gateway → `schema_violation`; the reviewer's forged vectors, controls intact |
| 2 | **The empty audience was not fail-closed.** Every surface documents `""` as the safe default, and plain equality made `"" == ""` **pass** — so a credential minted with `aud: ""` was universally presentable to exactly the verifiers the docs steer people toward. Found independently by two reviewers. | **high** | sentinel check in all three |
| 3 | **My parity harness was blind to its own purpose.** Its driver read the verifier's audience back off the object and applied that substitution itself, so it performed the override it was testing for. With the SDK override deleted — audience binding defeated end to end — it printed OK. It would **not** have caught the M29 defect it was written to stop recurring. | **high** (gate) | drives the GA verifier; the same sabotage now reddens two rows |
| 4 | **Python decompression bomb — a second revocation bypass.** The inflate budget ignored the declared `bit_len` and `decompress(…, max_length)` truncates silently, so 64 KB → 64 MB of zeros delivered an all-clear bitmap and a revoked passport verified VALID. My earlier guard in this milestone bounded only **from below**. | **high** | bounded both ways; 3 tests, control reddens 2 |
| 5 | **`ainra instance verify` never checked the proof-of-possession** — advertised as "what a receiving service does" and used as the M28 evidence transcript. `popSigningBytes` and `POP_MAX_SKEW_SECS` sat unreferenced; the dead constants were the tell. | medium | `instance present` added; verify refuses without a PoP; M28 transcript corrected in place |

## Confirmed open — recorded, not fixed

> **Resolved in M31 (2026-08-23) — see [PLAN-M31.md](PLAN-M31.md).** Seven of the eight below are closed by
> decisions D-049 through D-053. The eighth (wire malleability) is **still open** by decision: D-054 records why
> the fix requires an SDK API change, corrects this section's characterisation of it — it is a *verdict*
> divergence, not a reason divergence, and core is one of the permissive implementations rather than the strict
> one — and `make number-syntax` now pins it so it cannot drift. Two other notes below were also wrong in detail;
> M31 lists the corrections. The findings are left as written: they are the record of what was known that day.

These are real and need a decision rather than a patch. None is fixed today, and saying so is the point.

- **The PoP is not bound to the credential it accompanies** (both reviewers, independently). It signs
  `{aud, nonce, ts}` — no `iid`, no `ikey`, no credential digest. So a PoP captured from an honest presentation
  lets the capturer present *any* credential minted to that instance key at that audience, including a wider one
  or one from another lineage. Demonstrated across all three implementations. The documented nonce-cache mitigation
  does **not** help: the attack forwards a fresh, never-seen PoP with a substituted credential. **Fix is breaking**
  (add `iid` + a hash of the credential's signing bytes to the PoP body), which is why it is a decision, and it
  should be made before anyone depends on the current shape.
- **Python's delegation-chain expiry rule is structurally different from Rust's**, and one direction is fail-open:
  a hop expiring *before* the passport is accepted by Python and refused by Rust and TS. No vector can see it —
  the generator sets every hop `exp` equal to the passport `exp`.
- **`iid` is unbounded and echoed into the verdict event before the verdict is known.** A bundle refused at step 4
  still writes up to 200 KB of attacker-chosen text into the verifier's log, and the doc comment calling it "safe
  to emit: opaque and random by construction" is a promise made by the party the verifier does not trust.
- **Unbounded capability arrays** are an O(n×m) CPU amplifier at the instance rung (12 000 × 12 000 ≈ 0.4–0.9 s per
  presentation). Requires a registrar-signed passport, so insider-only.
- **The PoP window is 61 seconds, presenter-positionable**, not the 30 the constant reads as — `abs_diff` is
  symmetric, so a future-dated PoP is accepted.
- **`verify_wire` is still `pub` and still reads the wire audience**, and `WirePresentation.audience`'s doc comment
  still says "A presenter cannot set this". The M30 fix corrected the two entry points above it and left the layer
  below, so the comment is still false where it sits.
- **`site/verify.html` runs two engines** — WASM `verify` (no audience) and a JS fallback via `runVector` (wire
  audience) — which now disagree on instance credentials, and `wasm-differential` covers only `run_vector`.
- **Wire malleability**: `-0` and exponent notation are accepted by TS/Python and refused by Rust. Semantically
  identical values, no privilege gain, but a real three-way divergence in reason.

## What this says about the first pass

The self-refutation missed things a hostile reader found in an afternoon. Two of the fixes I reported as complete
were incomplete in the same file, one of the controls I named did not redden when reverted, and the gate I built to
end this class of defect could not see the class. That is the argument for an independent refute phase, made at my
own expense.
