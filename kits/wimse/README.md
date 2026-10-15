<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/wimse: an AINRA running copy as a WIMSE workload (D-076)

This kit tests AINRA's WIMSE layer against code that is not ours. `independent.mjs` is a WIMSE workload and a WIMSE
verifier built only from independent open-source libraries, pinned by exact version in `package-lock.json`:

- `jose` reads and mints the Workload Identity Token.
- `http-message-sig` handles RFC 9421.
- `structured-headers` finds the signature by its tag.

It imports nothing from AINRA. It is what a service that speaks WIMSE would run: it takes a trust domain and that
domain's issuer key, and it has no revocation.

| | Command | What it proves |
|---|---|---|
| Offline (CI) | `make wimse-check` | AINRA signs and the independent verifier accepts. The independent libraries sign and AINRA's `verifyWimseRequest` accepts. Each is tried on a GET, a GET with a query and a POST with a body. `--negative` flips the request signature, flips the WIT signature or changes the method, and every one of the 18 must be refused. |
| Live | `make wimse-e2e` (after `make live-up`) | A passport from the live registrar and a WIT signed by its key. The independent verifier and AINRA read every request. Both accept the copy's requests and both refuse a moved one. AINRA refuses a replayed nonce. After revocation, AINRA refuses the current passport at once and the old snapshot after F1 (30 s). The WIMSE-only verifier keeps accepting. |

Read [`docs/WIMSE.md`](../../docs/WIMSE.md) for how to use it. This is a test root over http on 127.0.0.1. It proves
the mechanism; it is not evidence that anyone deploys it.
