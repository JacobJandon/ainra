<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Security posture — the STAGING network (delta from the offline reference)

Putting the stack online adds attack surface. This states exactly what changes and, critically, **what an attacker
gains by fully owning the staging network: nothing about the future production root.**

## What an attacker who owns staging gets — and does not get

- **Gets:** the ability to issue/revoke TEST-ROOT credentials (if they also steal the write token), to serve
  tampered public artifacts from the staging origin, or to take staging down.
- **Does NOT get:** anything that migrates to production. Staging runs on a **TEST-ROOT** with **different keys**,
  labeled `X-AINRA-Root: test-root` on every artifact and page. The production root is born only at the recorded
  5-of-9 genesis ceremony (a pending DoD row); no staging key, directory, or credential is trusted by a production
  verifier. A verifier anchors to the root-signed directory it was configured with — staging's is not it.
- **Tampered artifacts fail closed at the verifier**, not at the server: a mutated checkpoint/status/credential
  breaks a signature or an inclusion proof, and `@ainra/sdk` returns INVALID. Owning the *serving* of public data
  cannot forge a *valid* verdict — the whole design.

## Read path — static, safe

The public artifact surface is `GET`-only static files (docs/ARTIFACTS.md § the contract): no keys, no compute, no state
to corrupt. Serve it read-only, behind a CDN. `X-AINRA-Network: staging` on every response.

## Write path — the new surface, guarded

The registrar `/issue`, `/revoke`, `/renew` endpoints mutate state. Hardening in `registrar-box`:

- **Auth:** when `AINRA_STAGE_ISSUE_TOKEN` is set (staging always sets it), write endpoints require
  `Authorization: Bearer <token>`; no token → `401`. The read path stays open (public data). The token is a
  bearer secret for a TEST-ROOT registrar — never production key control, never in an image or the repo (compose
  reads it from `deploy/.env`).
- **Rate limit:** a coarse token bucket (30 writes / 60 s) blunts abuse/DoS on the write path → `429`.
- **Body cap:** request bodies are capped (1 MiB) so a hostile `Content-Length` cannot force an allocation.
- **Bind:** expose only the ports you mean to; front TLS with standard ACME tooling (deploy/README.md), never
  reinvented in-process.

Proven by `make stage-smoke` step 4: an unauthenticated `POST /issue` returns `401`.

## Zero PII, zero telemetry

- **Artifacts + logs carry no personal data.** Operators are placeholders (`acme`/`globex`/`operator-NN`; the S7
  linter enforces no real names). The passport schema *rejects* PII/score/price fields (`deny_unknown_fields` +
  a recursive denylist). The transparency log records **what exists, never what agents did**.
- **Client surfaces stay telemetry-free** (AINRAscan makes zero cross-origin calls beyond fetching the artifacts it
  verifies). Server-side observability is self-hosted, ops-only (ADR-015) — Prometheus/Grafana/Loki on the operator's
  own infra; nothing phones home from a shipped component.

## Decisions (D-032)

Staging is deliberately a **different trust domain** from production (different root, different keys, labeled
everywhere). This is standard infrastructure practice — staging before mainnet — and it is what lets us put real
crypto online *now* without ever faking the production root. The write token is the only new secret; it protects a
throwaway TEST-ROOT registrar, and its compromise teaches an attacker nothing about the ceremony-born root.
