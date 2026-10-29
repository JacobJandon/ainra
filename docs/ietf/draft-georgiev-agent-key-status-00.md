---
title: "Status and Attribution for Externally Issued Agent Keys"
abbrev: "Agent Key Status"
docname: draft-georgiev-agent-key-status-00
category: info
submissiontype: independent
ipr: trust200902
area: Security
keyword: [AI agents, revocation, status list, attribution, transparency log]
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - fullname: Mihail Georgiev
    organization: AINRA
    email: info@ainra.org

normative:
  RFC2119:
  RFC8174:
  RFC7638:
  RFC8032:
  RFC8037:
  RFC6962:
  I-D.ietf-oauth-status-list:

informative:
  RFC9421:
  RFC7942:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204
    author:
      - org: National Institute of Standards and Technology
    date: 2024-08

--- abstract

Software agents increasingly sign their requests with keys issued inside one system: a signature directory, a
workload identity domain, a platform's own key store. A relying party in another organisation can verify such a
signature, but cannot learn who is accountable for the key or whether it has since been revoked, because revocation
exists only inside the system that issued it. This document specifies a link record: a signed, logged statement by an
accountable registrar that one existing Ed25519 key acts for one operator, carrying a status entry in a list any relying
party can check offline. It defines proof of control by the linked key, three kinds of revocation, a fixed verification
procedure, and reuse of the Token Status List format for the status itself.

--- middle

# Introduction

A relying party that receives a signed request from an agent typically answers one question: did this key sign this
request? It cannot answer two others that matter once agents act across organisations: which accountable party stands
behind the key, and whether that is still true. Short-lived credentials bound the damage of a stolen key by their
lifetime inside one provider; they do not tell a party outside that provider that a key has been withdrawn.

This document specifies a minimal layer for those two questions, for keys the agent already has:

- A **registrar** that has established the identity of an operator links an existing key to that operator, after the
  key itself has signed its consent.
- The link carries an entry in a status list in the format of {{I-D.ietf-oauth-status-list}}, together with an entry for
  the operator, so suspending the operator refuses every key linked to it.
- Every link and every revocation is appended to an append-only log {{RFC6962}}, so the log alone states which keys were
  ever attributable and when that ended.
- A relying party checks a link offline, in a fixed order, after it has verified the request's signature by whatever
  means it already uses.

The layer issues no new key to the agent and changes nothing in how requests are signed. It is complementary to
short-lived credentials: those bound risk inside one provider; a link carries attribution and revocation across
providers.

## Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

Operator:
: The organisation or person accountable for an agent.

Registrar:
: A party that has established an operator's identity under published rules, and signs link records. A relying party
  decides which registrars it trusts.

Linked key:
: An Ed25519 {{RFC8032}} public key named in a link record by its JWK thumbprint {{RFC7638}} {{RFC8037}}.

Link record:
: The signed statement defined in {{record}}.

# The link record {#record}

A link record is a JSON object, serialised in a canonical form (sorted member names, no insignificant whitespace,
integers only), and signed by the registrar over exactly those bytes. Its members are:

| Member | Content |
|---|---|
| `v` | the string `ainra-link-1` |
| `registrar` | the registrar's identifier |
| `passport` | the operator's identifier at that registrar |
| `subject` | `{kind: "jwk", alg: "Ed25519", thumbprint}`: the linked key's RFC 7638 thumbprint, base64url |
| `scope` | an array of capability strings, at most 256; empty means no narrowing |
| `nbf`, `exp` | the validity window, seconds since the epoch, `nbf < exp` |
| `status` | `{uri, idx}`: the link's own entry in the registrar's status list |
| `passport_status` | `{uri, idx}`: the operator's entry, in the same list, at a different index |
| `pop` | the linked key's signature over the consent bytes ({{pop}}), base64url |
| `log` | `{leaf}`: the log leaf hash of the record without its `log` member, base64url |

A record with any other member, a missing member, a member of the wrong type, or bytes that are not in canonical form
MUST be rejected. The `passport` identifier MUST name the same registrar as `registrar`.

## Proof of control {#pop}

Before issuing a link, the registrar MUST verify, and every relying party MUST verify again, a signature by the linked
key over the canonical object `{nbf, passport, purpose: "ainra-link-pop-1", registrar, thumbprint}`. Without it, anyone
could attribute a key they do not hold to an operator, or an operator to a key it does not control.

## Registrar signature

The registrar signs the canonical record bytes. The reference implementation signs with Ed25519 and ML-DSA-65
{{FIPS204}} together and requires both to verify; a deployment that profiles this document MUST state its signature
algorithms and MUST NOT accept a record whose required signatures are incomplete.

# Registrar operations

Issue:
: The registrar verifies proof of control, checks that the window lies inside the operator's own and that the scope is
  within what the operator may do, appends the record without its `log` member to its log, sets `log.leaf`, signs, and
  publishes. A key is linked at most once; a revoked key is never linked again.

Index:
: The registrar publishes all of its link records, with inclusion proofs under one signed checkpoint, as a single
  document fetched whole. It MUST NOT offer lookup by key: a relying party that asks about one key would reveal which
  agent it is dealing with.

Revoke:
: Three kinds. `link`: the linked key is no longer attributable; its entry is set. `operator`: the operator is
  suspended; the operator's entry is set, refusing every link to it. `compromise`: the key was stolen; its entry is set,
  and the revocation records `suspect_since`, the time from which the key's actions are not the operator's. A `link`
  revocation MAY later become a `compromise`; a compromise is never downgraded. Every revocation is appended to the
  log.

# Verification

A relying party has already verified a request's signature with an Ed25519 key, and holds a trusted set of registrars
with their signature keys, status keys, status list URIs and log keys. It checks a link in this order; the first
failure is the answer:

1. The record is well formed ({{record}}).
2. The registrar is trusted.
3. The status list is authenticated: signed by the registrar's status key, published under the URI the trusted set
   names, and that URI equals the record's `status.uri`. Nothing in the list is read before this holds.
4. The current time is within `[nbf, exp)`.
5. The registrar's signature over the record verifies.
6. The thumbprint of the key that verified the request equals `subject.thumbprint`, and `pop` verifies under that key.
7. If the request exercises a capability and `scope` is not empty, the capability is in `scope`.
8. The status list is fresh enough for the relying party's own policy; the link's entry is not set; the operator's
   entry is not set. An index at or beyond the end of the list is treated as set.
9. The checkpoint signature verifies, `log.leaf` is the leaf hash of the record without `log`, and the inclusion proof
   leads to the checkpoint's root.

A key with no link at all is "not linked": an outcome for the relying party's policy, typically refusal.

# Status

The status list uses the format of {{I-D.ietf-oauth-status-list}}: one bit per entry, least significant bit first,
compressed with DEFLATE in the ZLIB format. A registrar MAY publish additional signed forms of the same bits; a relying
party MUST check whichever form it trusts as authoritative. The reference implementation publishes a hybrid-signed
form as authoritative and the same bits as a `statuslist+jwt` for libraries that implement the Token Status List
draft.

# Implementation Status

(This section is to be removed before publication, per {{RFC7942}}.)

A reference implementation with three independently written verifiers (Rust, TypeScript, Python) and a shared corpus of
36 conformance vectors for link verification is available under open-source licences. It includes a registrar, gates
for HTTP servers and edge runtimes, and an interoperability test in which independent Token Status List and JOSE
libraries read the status list. It runs on a test network; no production deployment exists.

# Security Considerations

Stolen keys:
: `compromise` with `suspect_since` lets a relying party, an auditor or an insurer separate actions taken before the
  theft from those after. A relying party that keeps signed records of its decisions can later re-examine them.

Spliced status:
: A presenter could offer another registrar's list, or an old one. Step 3 binds the list to the registrar's status key
  and URI before any bit is read; freshness then bounds how long a superseded but genuine list can be replayed.

Consent forgery:
: Step 6 checks both the thumbprint and the proof of control. Checking only one lets an attacker obtain a record naming
  a victim's key with the attacker's consent, or the reverse.

Log binding:
: Step 9 binds `log.leaf` to the record's own bytes before checking inclusion; a record that points at another logged
  leaf is refused.

Registrar compromise:
: A registrar can link keys falsely. The append-only log makes every link visible to monitors; a relying party's trusted
  set may withdraw a registrar, and may limit trust to links logged before a given leaf.

Quantum:
: Link records live as long as their windows. A deployment that needs assurance beyond the life of classical signatures
  should require a post-quantum signature alongside Ed25519, as the reference implementation does.

# Privacy Considerations

A link names a key and an operator; it holds no personal data. Relying parties fetch whole indexes and whole status
lists, so no request reveals which agent is being checked. Registrars hold whatever evidence they used to establish the
operator's identity; none of it appears in the link.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This work builds on the Token Status List draft of the IETF OAuth working group, on Certificate Transparency, and on the
working groups exploring agent identity, whose drafts made the cross-provider gap visible.
