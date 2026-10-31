<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M49 — Logged decision heads, and Link for secp256k1 keys

Two items from PLAN-M47 § Later, approved by the owner on 31 October 2026: gates publish their decision-log heads into
the registrar's transparency log (D-081), and Link accepts secp256k1 keys (D-082). Both change what is signed, so
each lands the way Link and decision records did: the rule in core, a shared corpus, the three implementations held
to it by `make diff`, then the surfaces, then docs. Nothing here touches the passport wire format.

## D-081 — A decision log's tail is visible once its head is logged

**The gap.** A decision log is a hash chain signed by the gate's key. Deleting, editing or reordering a record breaks
the chain; cutting records off the end does not (vector `d17`). `ainra verify-decisions --head` catches a cut only if
the checker already holds a head the gate cannot quietly replace, and today the only head is the gate's own
`/.well-known/ainra-decisions-head`, which the gate can rewrite.

**The design.**

- A **head statement** is a closed object the gate signs with its decision key:
  `{v: "ainra-decision-head-1", gate, seq, at, head}` — the gate's id (its key thumbprint), the `seq` and `at` of the
  last record, and that record's line digest. Canonical bytes, Ed25519, same rules as a decision record.
- The registrar accepts statements at **`POST /decision-head`** `{statement, sig, gate_key}`: it checks the signature
  and that `gate` is the thumbprint of `gate_key`, appends the statement (without `sig`, like a link body) to its
  transparency log under its own leaf domain, and answers with a **head receipt**: the statement, the signature, the
  leaf index and an inclusion proof under a delegate-signed checkpoint. It interprets nothing else: it does not see
  the decisions, only a digest. Open write (the statement is self-authenticating) with its own rate limit and a
  per-gate floor: a statement whose `seq` is below one already logged for that gate is refused, so the registrar's
  log alone shows a gate going backwards.
- **Verifying a log against a receipt:** the receipt verifies (signature by the gate key, inclusion to a checkpoint
  signed by the registrar's log key); the chain verifies as today; then the chain must reach `seq`, and the record at
  `seq` must have digest `head`. A chain shorter than `seq + 1` is a new problem, **`truncated`**; a record at `seq`
  with a different digest is **`forked`**. Records after `seq` are fine — the log grew after it was anchored.
- **Gates** publish on a schedule, not per decision: the pilot gets `--publish-head URL` with "every N decisions or T
  seconds, whichever first"; the SDK's `createDecisionLog` gains `statement()` so any gate can do the same.

**Steps.** *Steps 1–4 and 6 done 2026-10-31 (2a6432d, f559fed, and the commit that adds the corpus); step 5 next.*
1. Core (`ainra_core::decision`): `HeadStatement`, its signing bytes, `verify_head_receipt`, `verify_chain_to_head`
   with the two new problems. Unit tests.
2. Registrar: `POST /decision-head`, the leaf domain, per-gate floor, persistence across restart (the D-080 test
   pattern). `GET /decision-heads` (whole list, as `/links`).
3. Corpus `vectors/v1-decision` extended: valid anchor, grown-after-anchor, truncated, forked, statement signed by
   another key, gate/key mismatch, receipt with a bad inclusion proof, checkpoint not signed by the registrar.
4. TypeScript and Python mirrors, held to the corpus in `make diff`; `ainra verify-decisions --receipt`.
5. Pilot `--publish-head`; `make pilot-e2e` cuts the tail of a real log and the receipt catches it (the witness).
6. Docs: DECISION-RECORDS.md, the D-081 record, OpenAPI, CHANGELOG.

## D-082 — Link accepts secp256k1 keys (ES256K)

**Why.** Agent networks that live on ledgers sign with secp256k1. Link v1 takes only Ed25519, so it cannot attribute
those agents' keys or revoke them across networks, which is the gap the 28 October research found.

**The choice: ES256K, as JOSE defines it (RFC 8812).** ECDSA over secp256k1 with SHA-256. The key is named by its RFC
7638 thumbprint over `{crv: "secp256k1", kty: "EC", x, y}`. Signatures are the 64-byte `r || s` form and **must be
low-S**; a high-S signature is refused, so a signature cannot be re-encoded into a second valid one. Ledger-specific
message formats (for example a keccak-hashed personal-sign envelope) are a different `alg` and are not in this
milestone — ES256K is the standard, ledger-neutral form, and a later `alg` can be added beside it the same way.

**Wire changes, additive.** `subject.alg` becomes `"Ed25519"` or `"ES256K"`. `LinkSpec` gains `alg` (default
`Ed25519`, so every existing caller is unchanged); for ES256K, `key` is the 33-byte compressed SEC1 point,
base64url. Proof of control is the same consent bytes, signed with the key's own algorithm. Verifiers take the
presented key together with its algorithm; a bare 32-byte key keeps meaning Ed25519. Existing links and vectors are
untouched.

**Libraries, audited only.** Rust: `k256` from RustCrypto, pinned to the 0.13 line that NCC Group reviewed in 2023
(two high-severity findings, both fixed before release; the crate still says "use at your own risk", and our docs
will repeat that). TypeScript: `@noble/curves` `secp256k1`, already a dependency. Python: `cryptography`
(`ec.SECP256K1`), already a dependency.

**Steps.**
1. Core (`ainra_core::link`): `alg` on the subject, ES256K thumbprint, low-S verification, consent check per alg.
   Unit tests, including a high-S signature refused.
2. Registrar `/link` and `/demo/link` take `alg`.
3. Corpus `vectors/v1-link` extended: valid ES256K link, high-S consent, thumbprint over the wrong curve, an Ed25519
   key presented against an ES256K link and the reverse, an uncompressed or off-curve point, a 32-byte key claimed as
   ES256K.
4. TypeScript and Python mirrors, `make diff` and `make link-parity`; CLI `ainra link --alg ES256K`.
5. Docs: LINKS.md, the D-082 record, the Internet-Draft (`alg` registry instead of "one Ed25519 key"), OpenAPI,
   CHANGELOG.

## Order and done

D-081 first: it closes a gap in a published guarantee, and it changes no key handling. Then D-082. Each step is
preflight-green, staged before the tracked-file gates, clean-clone checked where CI changes, and pushed on its own.
Done means: both corpora pass in all three implementations, the live drills still pass, and the docs say exactly what
exists.
