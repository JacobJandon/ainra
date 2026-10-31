<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M47 — Link, decide, serve: the hybrid release

Written 2026-10-26 after three research passes (who revokes agent credentials today, how neutral global roots were
built, how to run online verification). The sources are in `docs/LANDSCAPE.md` and `docs/REGULATION.md`; the
findings that changed this plan are quoted where they apply.

## The finding that shapes everything

Nobody ships a neutral, cross-provider, offline-checkable revocation status for credentials someone else issued.

- Every player revokes inside its own domain: a tenant, a card network, one directory, one chain.
- The IETF has standardised the bitstring (OAuth Token Status List, in the RFC Editor queue) and point-to-point push
  between parties already configured to talk (OpenID SSF/CAEP). Neither answers the open-world question: *this key,
  from any issuer, belongs to an accountable operator, and is or is not revoked.*

That question is AINRA Link.

## What does not change

- The passport, the root, the ceremony design, the six charter prohibitions.
- Offline verification, failing closed, the transparency log.
- The frozen normative documents (Standard, technical specification, DESIGN.md) and `reasons.json`.
- Every existing corpus and API, except the published-surface cleanup in step 6, which ships in 0.6.0.
- The website. Nothing in this plan touches `site/` without the owner's separate approval.

## The steps

### 1. AINRA Link — status and attribution for credentials agents already have

- A registrar signs a **link record**:
  - the credential, keyed on a normalised subject: an RFC 7638 JWK thumbprint (signature-agent and workload keys) or
    `client_id@issuer` (OAuth);
  - the operator's passport;
  - an optional scope narrower than the passport's;
  - a validity window;
  - a bit in the registrar's existing signed status list.
- **Proof of control.** Creating or rotating a link requires a signature by the linked key itself. This closes the
  hole the signature-agent registry draft names: "malicious actors may put properties which are not theirs in the
  registry".
- **Three kinds of revocation, kept distinct:**
  - *link revoked*: this key is no longer attributable;
  - *operator suspended*: every link of the passport flips;
  - *key compromised*: carries `suspect_since`, so actions after that time can be told apart from earlier ones.
- **Every link, unlink and revocation is appended to the registrar's log.** Completeness can then be audited: the
  argument that made CRLite work.
- **Verification, two ways:**
  - *pull*: no change for agents. The verifier already checked the agent's signature; it looks up that key's
    thumbprint in the registrar's signed, cacheable link index and checks the bit offline.
  - *push*: the agent sends the link record once, then a digest, reusing send-once.
- **The answer** is accept or refuse, plus the operator and passport, with distinct reasons for unlinked, stale and
  revoked. Reasons reuse the frozen set; a new one goes through the amendment check first.
- **Rust core first** (`crates/ainra-core`), then independent TypeScript and Python implementations held to a new
  public corpus, `vectors/v1-link`, in `make diff`.

### 2. Standard status format alongside our own

- The registrar's status list already uses the Token Status List bit layout.
- Each registrar also publishes the same bits as a signed `statuslist+jwt`, so any Token Status List library can
  check AINRA links.
- AINRA's hybrid-signed list stays authoritative. The standard envelope is a compatibility mirror, signed with the
  registrar's Ed25519 key, and says so.

### 3. Signed decision records

- Every gate decision becomes a small record:
  - the agent or linked key, and the operator;
  - accept or refuse, and why;
  - digests of the request, never its body;
  - the status sequence and checkpoint the decision used.
- The record is signed by the gate's own key and chained into a tamper-evident local log.
- The same format is the receipt the online verifier returns (step 5).
- It serves the "durable audit logs" of the IETF agent-identity draft, AI Act Art. 12 logging, and the Financial
  Stability Board's "reconstruction of actions". It holds no personal data.

### 4. Gates, CLI, MCP, live drills, pilot kit

- **Gates:** Node, edge and Python gates gain link mode and an optional decision log.
- **CLI:** `ainra link`, `ainra verify-link`, `ainra verify-decisions`.
- **MCP:** a link-checking tool.
- **Live drills:** revoke a link, and AINRA refuses while the signature-agent verifier and the workload verifier, each
  alone, keep accepting. Added to `make live-drills`, which CI runs.
- **Pilot kit:** `kits/pilot` puts a link-mode gate in front of any endpoint with one command.

### 5. Online verification — so AINRA does something, without becoming a single point of trust

The research is unanimous: a per-credential live query is the anti-pattern. OCSP leaked browsing, soft-failed and was
switched off; Let's Encrypt turned its responders off on 6 August 2025. The design follows CRLite, CT tiles and the
public transparency-log service instead.

- **Static first.** The signed artefacts verifiers already use, served as content-addressed files:
  - the status lists;
  - the link indexes;
  - the checkpoints;
  - the log in C2SP tiles.
  Anyone may mirror them, and signatures make mirrors interchangeable.
- **Whole-list download is the privacy model.** Lists of at least 131,072 entries with random index allocation, so a
  fetch reveals nothing.
- **A stateless hosted verifier, `POST /v1/verify`.**
  - It runs the published verifier at a pinned build hash.
  - Every answer is a signed decision receipt that embeds what the decision used, so the caller can re-check it
    offline.
  - It is a convenience, not an authority.
- **No lookup by full identifier, no search, no "list agents", no unsigned verdicts, no soft-fail.** Logs hold
  aggregate counters only, never a thumbprint or a name.
- **Push is a doorbell only.** A server-sent-events stream announces a new sequence and hash; receivers must pull and
  verify. An SSF/CAEP transmitter for enterprise receivers comes later.
- **Commitments, published:**
  - 99.5% for the API, 99.9% for static files;
  - a status page;
  - incidents acknowledged within one business day;
  - postmortems.
- **Operation needs the owner.** The code and deploy configuration are built here; where it runs, and the account,
  are the owner's decision. Nothing is provisioned without it.

### 6. Safe published surfaces (0.6.0)

- The corpus-replay functions move to a separate `conformance` entry point in the TypeScript and Python packages.
- The MCP tool loses its fixture mode.
- Trusted inputs and presented inputs become different types, so a bundle can never vouch for itself.

### 7. Standards

- An individual Internet-Draft: *status and attribution for externally issued agent keys*. It defines the link record,
  proof of control, the lookup and verifier behaviour, and reuses Token Status List.
- Aimed at the OAuth, Web Bot Auth and agentproto working groups. It is complementary to short-lived credentials:
  those bound risk inside one provider, Link carries attribution and revocation across providers.
- The owner submits it.

### 8. The path to a recognised neutral NGO

- **The working precedent is the Legal Entity Identifier system.**
  - A not-for-profit Swiss foundation, GLEIF, is the root and "the Root of Trust for the vLEI Ecosystem".
  - Accredited issuers issue; GLEIF issues nothing itself.
  - A committee of regulators oversees it.
  - Funding is cost recovery only, with "no monopoly rents".
  - It began with a G20 request and an FSB design, and was then required by EU financial rules.
- **Write the path down in `docs/GOVERNANCE-PATH.md`:**
  - now, as an individual: grants, standards participation;
  - an interim legal home: a Bulgarian public-benefit foundation, or a fiscal host;
  - borrowed legitimacy: a recorded ceremony with keyholders from at least three regions, two or three independent
    registrars, one external audit, an interim oversight committee;
  - a permanent neutral entity, a Swiss foundation or a Belgian international non-profit, with regional board quotas;
  - formal recognition: an RFC, citation by NIST and the EU, an international body calling agent revocation a public
    good.
- **No rename.** The owner decides the legal form.

### 9. The ceremony moves after the first design partner

The public gates and the Definition of Done are unchanged. `ROADMAP.md` and `campaign/PLAN.md` say so.

### 10. Funding now

The NLnet Restack application is sharpened with this evidence before 3 November 2026, 12:00 CET. The owner submits.

## Order

1. NLnet, the regulation map, this plan, D-078 (Link), D-079 (decision records and online verification), the
   governance path.
2. Link in the core, its corpus, the registrar endpoints and log entries.
3. Link in TypeScript and Python, the gates, CLI and MCP; live drills.
4. Decision records.
5. The Token Status List mirror; the online verifier and static publishing (code and config only).
6. The pilot kit; safe published surfaces for 0.6.0; the Internet-Draft.

Each step ends green on preflight, the audit, and the changed CI jobs from a clean clone, then is committed.

## Later — decided, not dropped

The owner chose to defer these on 28 October 2026. Each stays listed here until it is done.

- **A public demo door for links** (`POST /demo/link`, staging only, demo specimens only), so a visitor can link a
  key from a browser. *The door is built (2026-10-31: `POST /demo/link` and `/demo/link/revoke`, tested against the
  real binary in `services/ainra-services/tests/demo_link_door.rs`). The browser step that uses it is on get.html
  — a key made in the browser, linked, verified, revoked — and runs wherever a registrar is reachable, as minting
  does.*
- **More key types for links.** Version 1 links Ed25519 keys. Networks whose agents use other curves, such as the
  secp256k1 keys common on ledgers, need a new `alg` and vectors first.
- **The tail of a decision log.** Records cut from the end are invisible without a published head; gates should
  publish their head somewhere they cannot quietly rewrite. The format exists (`--head`); where to publish it does not.

