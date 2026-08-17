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
report publishes only the SHA-256 of the subject for the same reason: a named probe subject is a marked probe.

**Run it unannounced.** A known schedule is an audit date, and the point of this kit is that audit dates were never
where the failures were found.

## Proving the instrument works

```bash
make probe-drill      # from the repo root
```

Runs the probe against an honest registrar, then against four dishonest ones
([`dishonest-registrar.mjs`](dishonest-registrar.mjs)), requiring the **named** check to fail each time. The four are
real behaviours, not synthetic errors — the sharpest is `suppress-revocation`, which forges nothing: every byte it
serves was signed by the real registrar, it just keeps serving a genuine pre-revocation snapshot forever.

A probe that has never been shown failing is decoration. This is how we know it isn't.
