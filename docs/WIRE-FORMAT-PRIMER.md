<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# The wire format, from first principles

**Who this is for.** Someone in a future where none of this project's code runs, holding a passport and needing to
know what it says and whether to believe it. Everything below is derivable from public standards and this page. No
AINRA software is required, and none is referenced as an authority — where this document and the code disagree,
that is a defect in this document.

**How it is checked.** `make legibility-drill` implements a parser from this page alone, using nothing but a
standard library, and runs it against the published conformance corpus. If the primer is wrong or incomplete, that
drill fails.

---

## 1. The outer object

A presentation is **JSON** (RFC 8259). Every binary field inside it is **base64url without padding** (RFC 4648
§5): the alphabet is `A–Z a–z 0–9 - _`, and `+` `/` `=` never appear.

```
{
  "claims":           "<base64url of the claims JSON>",
  "issuer_sig":       { "ed25519": "<b64u>", "mldsa65": "<b64u>" },
  "leaf_index":       <integer>,
  "inclusion_proof":  [ "<b64u 32 bytes>", … ],
  "checkpoint":       { "origin": "<string>", "size": <integer>, "root": "<b64u 32 bytes>" },
  "checkpoint_sig":   { … },
  "status_list":      "<b64u of a zlib stream>",
  "status_len":       <integer>,
  "status_issued_at": <unix seconds>,
  "freshness":        "F1" | "F2" | "F3",
  "now":              <unix seconds>
}
```

## 2. Canonical JSON

Signatures and hashes are computed over **canonical JSON** — RFC 8785 (JCS). Two rules carry almost all of it:

1. **Object keys sorted** by their UTF-16 code units, ascending.
2. **No insignificant whitespace**: no spaces after `:` or `,`, no newlines, no indentation.

Numbers are integers throughout this format; a value written `2.6e3` is not canonical even though JSON considers
it equal to `2600`. (Implementations differ on whether they *reject* it — see D-054 — so a parser should
canonicalise from the parsed value, never from the received text.)

## 3. The claims

Base64url-decode `claims` and parse as JSON:

| Field | Meaning |
|---|---|
| `vct` | credential type — a constant string identifying this as an agent passport |
| `iss` | the issuer, as `did:ainra:<registrar>:<operator>:<lineage>` |
| `sub` | the subject, as `ainra:<registrar>:<operator>:<lineage>@<version>` |
| `nbf`, `exp` | validity window, Unix seconds, compared **exactly** — `nbf ≤ now < exp` |
| `keys` | the subject's public keys; `keys[0]` is the control key |
| `capabilities` | what this agent may do |
| `scope_ceiling` | the maximum it may ever hold; `capabilities ⊆ scope_ceiling` |
| `act_chain` | delegation hops, if any — each may only narrow |
| `status` | `{ "status_list": { "idx": <integer>, "uri": "<string>" } }` — where revocation is published, and this lineage's bit |
| `log` | where the credential sits in the transparency log |
| `tier`, `authority`, `cnf` | assurance level, authority class, key confirmation |

## 4. Two signatures, and both must verify

`issuer_sig` carries **Ed25519** (RFC 8032) and **ML-DSA-65** (FIPS 204). Both are over the canonical claims bytes.

**Both-or-invalid.** A presentation with one valid signature and one invalid is **invalid**, not "partially
valid". This is the property that makes the format survive either primitive being broken: an attacker who breaks
Ed25519 still cannot forge, because ML-DSA-65 still has to verify, and vice versa.

Ed25519 alone can be verified with almost any standard library. ML-DSA-65 needs a post-quantum implementation; a
reader who has one can check both, and a reader who has only Ed25519 can check *half* and must say so rather than
report success.

## 5. Logged before valid

A credential is not valid merely because it is signed; it must be **in the public log**. That is proved by an
RFC 6962 inclusion proof.

**The leaf.** Take the claims JSON, **remove the `log` member**, canonicalise the remainder (§2), and hash:

```
leaf_hash = SHA-256( 0x00 || canonical_claims_without_log )
```

The `log` member is removed because it names the position the leaf is being placed at, and a leaf cannot commit to
its own address.

**Interior nodes** are `SHA-256( 0x01 || left || right )`. The `0x00` / `0x01` prefixes are what stop a leaf from
being reinterpreted as an interior node.

**The proof.** RFC 6962 §2.1.1: walk `leaf_index` within `checkpoint.size`, consuming `inclusion_proof` entries as
siblings — at each level, if the current index is odd the sibling is on the left, otherwise on the right — and the
result must equal `checkpoint.root` exactly.

**The checkpoint** is signed by the log's key (`log_root_key` in the directory). An unsigned checkpoint proves
nothing: it is the log asserting its own root.

## 6. Revocation

`status_list` is base64url of a **zlib** stream (RFC 1950). Decompress it to a bitmap of `status_len` bits, packed
**8 bits per byte, least-significant bit first** — bit `n` of the list lives in bit position `n mod 8` of byte
`n div 8`, counting from the low end of the byte:

```
byte  = bitmap[ idx / 8 ]
bit   = ( byte >> (idx % 8) ) & 1
revoked = (bit == 1)
```

(This document originally said *most*-significant-bit first. `make legibility-drill` caught it on the first run —
twenty revoked credentials read as valid, which is the worst direction for an error of this kind to run. The order
above is what `ainra-core` and the independently-written Python verifier both do.)

**Out of range is revoked, not valid.** If `idx` exceeds the bitmap, the answer is *revoked*. This is the whole
fail-closed posture in one rule: an answer that cannot be found is never read as permission.

**Freshness.** `status_issued_at` must be within the window named by `freshness` — F1 = 30 s, F2 = 5 min,
F3 = 24 h. A status list older than its class is `stale_status`, and stale is refused. **The verifier chooses the
class**; a presenter that picks its own would choose the laxest.

## 7. Trust anchors

Nothing above tells you *who was allowed to sign*. That comes from a **root-signed directory**, held by the
verifier, never supplied by the presenter — a presenter that supplied its own anchors would be naming its own
authority. The directory maps each registrar to its `issuer_key` and `log_root_key`, and is itself signed by the
root keys.

A mirror must therefore carry the directory and root keys alongside the credential; a conformance vector embeds its
own anchors, which makes it self-contained for testing and is **not** how a real credential works.

## 8. The order of checks

Order matters, because the first failure is the reason reported and a good reason sends a debugger to the right
place:

1. schema and name grammar
2. issuer accredited in the directory
3. validity window
4. both signatures
5. delegation chain narrows
6. status freshness, then revocation
7. inclusion proof to a signed checkpoint

## 9. What a reader with only a standard library can check

| | Checkable with a standard library alone? |
|---|---|
| structure, base64url, canonical JSON | yes |
| validity window, scope ⊆ ceiling, chain narrowing | yes |
| the leaf hash and inclusion proof (SHA-256) | yes |
| revocation bit and freshness (zlib) | yes |
| Ed25519 signature | yes, in most languages |
| ML-DSA-65 signature | **no** — needs a post-quantum implementation |

A reader without ML-DSA can establish everything except the post-quantum half of the signature pair. That is a
real and useful amount — enough to detect a forged log position, a revoked credential, or an expired one — and it
must be reported as *partial verification*, never as valid.
