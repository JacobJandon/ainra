<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA compliance probe

Measure a registrar's accreditation invariants **from outside, holding nothing it issued you.** The term this
implements is [`docs/PROBES.md`](../../docs/PROBES.md); the reasoning is [D-046](../../docs/DECISIONS.md).

```bash
npm install                       # links @ainra/sdk from the repo
node probe.mjs --registrar https://registrar.example \
               --directory directory.json --roots roots.json --now $(date +%s)
```

`directory.json` and `roots.json` are the root-signed directory and the ceremony root keys — the same two files any
verifier holds. Nothing else is needed, and in particular **no credential from the registrar being measured**. Exit
code 0 = COMPLIANT, 1 = NON-COMPLIANT or INVALID-RUN. `probe-report.json` carries every check, the measured revocation
latency, and the skip reasons.

| Flag | Default | |
|---|---|---|
| `--slo-revocation-sec` | 60 | the SLO the run is scored against |
| `--poll-ms` | 200 | how often to re-present while waiting for the revocation |
| `--timeout-sec` | 240 | give up waiting; a miss is recorded as a miss |
| `--out` | `out` | where `probe-report.json` is written |

## Read this before you run it against something you operate

**P0 is not a formality.** The probe sends an unauthenticated write and requires a refusal. If the write succeeds the
run is **VOID** — reported as `INVALID-RUN`, not as a failure — because a probe with effective write access is the
operator measuring itself, which is the self-report this whole kit replaces. Do not pass it a token. Do not "helpfully"
allowlist it.

**Do not mark the probe.** No reserved operator name, no header, no account flag, no cache exemption. A registrar that
can tell the probe from a customer will eventually treat it differently, and then the measurement is worth nothing. The
report publishes the subject only as a salted commitment, SHA-256(salt ‖ subject), for the same reason: a named probe subject is a marked probe, and so is a plain hash of its name, which the registrar finds by hashing every name in its own log. The salt is written beside the report as `probe-subject.secret.json` (owner-only) and is revealed when the probe identity retires; `node commitment.mjs --drill` shows both halves.

**Run it unannounced.** A known schedule is an audit date, and the point of this kit is that audit dates were never
where the failures were found.

## Proving the instrument works

```bash
make probe-drill      # from the repo root
```

Runs the probe against an honest registrar, then against five dishonest ones (four through
[`dishonest-registrar.mjs`](dishonest-registrar.mjs), and the real registrar built to revoke only one generation of a
renewed lineage), requiring the **named** check to fail each time. All five are
real behaviours, not synthetic errors — the sharpest is `suppress-revocation`, which forges nothing: every byte it
serves was signed by the real registrar, it just keeps serving a genuine pre-revocation snapshot forever.

A probe that has never been shown failing is decoration. This is how we know it isn't.

## The ladder: from reports to notices (D-096)

```bash
node probe.mjs … --vantage vp-a --network net-1 --out a     # each vantage point says where it stood
node probe.mjs … --vantage vp-b --network net-2 --out b
node notice.mjs step --state ladder/registrar-11.json --now $(date +%s) --registrar registrar-11 a/probe-report.json b/probe-report.json
node notice.mjs evidence --state ladder/registrar-11.json --for DISTRUST_FROM_LEAF --now $(date +%s) --out evidence.json
```

A failure becomes a notice only when the same check fails from two vantage points on distinct networks. The ladder
waits its days (D-094: a 30-day cure, notices 14 days apart, 90 days of grace before WITHDRAW), and `evidence`
refuses, by name, until the ladder allows it. Its output is the `evidence` an adverse request carries, and
`ainra directory check-request` holds it to the same numbers. `node notice.mjs --drill` shows every rung waiting.

