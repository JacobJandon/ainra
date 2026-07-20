<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Runbook: incident basics
- **Suspected key/token compromise:** rotate the write token (deploy/runbooks/key-rotation.md) FIRST; audit
  `/records` for unexpected issuances; revoke them (`POST /revoke`). A TEST-ROOT compromise migrates NO trust to
  production (docs/SECURITY-STAGING.md) — do not conflate it with a production incident.
- **Tampered public data reported:** it fails closed at every verifier by design. Re-publish from a healthy
  registrar; `make verify-mirror` each edge; purge only mutable objects from the CDN (immutable ones are safe).
- **A witness alarms on a fork:** STOP publishing; investigate which checkpoint forked; a fork means a log/writer
  bug or compromise — never override a witness refusal.
- **Down:** the read path is static/CDN — survives registrar outages. Restart via deploy/runbooks/deploy.md.
