<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: key rotation (staging)
- **Write token:** set a new `AINRA_STAGE_ISSUE_TOKEN` in `deploy/.env`; `docker compose up -d` the registrars.
  Old token stops working immediately (401). Update any authorized issuer client.
- **Status/checkpoint delegate certs:** the daemon certifies its delegates under the TEST-ROOT (≤92-day cap,
  ADR-002). On the wall clock (the default; `make live-up`) it **renews them itself**: at startup and on every
  request it re-certifies the same delegate key from the current time once the cert is within 14 days of expiry.
  If it cannot, it refuses to start, and once running it answers 503 rather than sign with a lapsed cert (D-064).
  There is nothing to do by hand. A restart does **not** rotate anything — the delegate keys derive from the
  registrar seed, and on a pinned network (`AINRA_CLOCK=pinned`, the reproducible staging world) the certs stay in
  their fixed 2026-04 window by design. `make live-status` reads the window from a real presentation. A revoked
  delegate's checkpoints go `checkpoint_invalid` (M4) — publish the revocation in the directory.
- **The TEST-ROOT itself:** not rotated in staging; the production root is a separate, ceremony-born key
  (docs/SECURITY-STAGING.md). Never reuse staging key material for production.
