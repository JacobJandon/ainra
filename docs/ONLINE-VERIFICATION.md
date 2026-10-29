<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Online verification: static first, and never an authority

AINRA verification works offline. Online verification exists for people who would rather not run a verifier, and it
is built so that it can never become the thing everyone has to trust. Decision: [D-079](DECISIONS.md).

**Why static first.** Asking a server about one credential at a time leaks what you are checking, fails open when
the server is slow, and makes the server an authority. That is how OCSP ended: Let's Encrypt switched its responders
off on 6 August 2025. AINRA follows the designs that replaced it: download whole signed lists, check them yourself.

## The two halves

### 1. Static artefacts, served by anyone

`tools/publish-static.mjs` copies each registrar's signed artefacts into plain files:

| File | What it is |
|---|---|
| `<registrar>/status-list.json` | the hybrid-signed status list (authoritative) |
| `<registrar>/status-list.jwt` | the same bits as an IETF `statuslist+jwt` ([kits/tsl](../kits/tsl)) |
| `<registrar>/links.json` | the whole link index ([LINKS.md](LINKS.md)) |
| `sha256/<digest>` | every file above, also under its own SHA-256, never deleted |
| `heads.json` | what is current |

Every file carries its own signature, so the registrar, a CDN and a volunteer mirror are interchangeable: a verifier
trusts the signature, not the host. Lists are downloaded whole, so a fetch says nothing about which agent is being
checked. Run the publisher on a timer inside the freshness class you serve (F1 30 s, F2 5 minutes).

```
node tools/publish-static.mjs --out public --registrar https://registrar.example --directory D --roots R
```

### 2. A hosted verifier, as a convenience

`services/verify` answers `POST /v1/verify` with `{passport}` or `{link, key, capability?}`. It runs the published
verifier, `@ainra/sdk`, against the directory it is configured with, and returns:

- `decision`: accept or refuse, with the named reason, and the operator on acceptance;
- `receipt`: a signed decision record ([DECISION-RECORDS.md](DECISION-RECORDS.md)), bound to the exact bytes you
  sent, naming the verdict and digests of the status and checkpoint it relied on.

A receipt re-checks offline: `ainra verify-decisions receipt.jsonl --gate-key <verifier_key from /v1/about>`.
`/v1/about` also states the commit the service was built from. Anyone can skip the service and get the same answer
from `@ainra/sdk` locally.

**What it will not do, by design:**
- no lookup by identifier, no search, no listing of agents or keys: you send what you want checked;
- no unsigned verdicts and no soft-fail: anything it cannot decide is a signed refusal;
- no request bodies or identifiers in logs. `/v1/metrics` returns aggregate counts only.

`/v1/events` (with `--heads URL`) is a doorbell: it announces that `heads.json` changed. Receivers must still fetch
and verify. A push channel that carried status would be one a network attacker could suppress.

## Commitments, once it runs

These are the targets the operator will publish when there is a host. They are not in force today: nothing is
deployed.

| | Target |
|---|---|
| Static files | 99.9% monthly availability |
| `POST /v1/verify` | 99.5% monthly availability |
| Status page | public, with incident history |
| Incidents | acknowledged within one business day; a public post-mortem for every outage |

When the service is down, verifiers that use the static files are unaffected, and verifiers that use neither are
unaffected by definition.

## Running it

```
node services/verify/server.mjs --new-key verifier.key
node services/verify/server.mjs --directory directory.json --roots roots.json --key verifier.key --freshness F2
docker build -f services/verify/Dockerfile --build-arg AINRA_BUILD=$(git rev-parse HEAD) -t ainra-verify .
```

`make online-verifier-check` runs both halves against real artefacts: receipts that verify and bind the request, an
edited receipt refused, no lookup paths, aggregate-only metrics, and published files that match their digests and
verify wherever they are served.

**Where it runs is the owner's decision.** The code and the deploy configuration are here; no account or host has been
provisioned.
