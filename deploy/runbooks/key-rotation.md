<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: key rotation (staging)
- **Write token:** set a new `AINRA_STAGE_ISSUE_TOKEN` in `deploy/.env`; `docker compose up -d` the registrars.
  Old token stops working immediately (401). Update any authorized issuer client.
- **Status/checkpoint delegate keys:** the daemon issues delegate certs under the TEST-ROOT (≤92-day cap, ADR-002).
  Rotation = restart with fresh delegates; verifiers accept the new certs chained to the same root. A revoked
  delegate's checkpoints go `checkpoint_invalid` (M4) — publish the revocation in the directory.
- **The TEST-ROOT itself:** not rotated in staging; the production root is a separate, ceremony-born key
  (docs/SECURITY-STAGING.md). Never reuse staging key material for production.
