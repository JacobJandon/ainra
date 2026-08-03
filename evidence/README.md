<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Intake — how strangers hand us evidence

Three Definition-of-Done rows in `docs/DOD.md` can only be moved by people who are not us. This directory is how
their artifacts arrive: **as a pull request that verifies itself in CI.**

| You want to | Submit | CI does | The row moves when |
|---|---|---|---|
| Prove you verified AINRA independently | `evidence/verifier/<your-id>.json` | public checks (signature, shape, corpus hashes, nonce) | **≥3 distinct valid attestations**, each confirmed against the maintainer's private answer key |
| Run a witness | `evidence/witness/<candidate-id>.json` | shape check + a probe of your declared endpoint | never automatically — candidacies are candidacies |
| Hold a custodian share | (no file) — the ceremony packet | nothing; it is a conversation | at the recorded ceremony |

**Nothing here flips a DoD row.** CI validates the *public* half of a submission. The decisive check — that you
actually executed verification against a challenge only you and the maintainer could answer — needs a private
answer key that is deliberately not in this repository. The maintainer runs it, and `make genesis-status` counts
only signature-checked evidence. A green CI comment means "well-formed", never "counted".

---

## 1. Verifier attestations (`evidence/verifier/`)

**The ask:** ~10 minutes, on your machine, offline. You get a challenge — a small folder of fresh artifacts whose
answers you cannot precompute — verify it with the published tooling, and send back the signed result.

```sh
git clone https://github.com/JacobJandon/ainra && cd ainra
make verify-as-external CHALLENGE=/path/to/your/challenge   # writes verifier-attestation.json
node tools/intake-check.mjs verifier-attestation.json       # the same checks CI will run
```

Then open a PR that adds it as `evidence/verifier/<your-id>.json` (kebab-case id you choose, e.g. `evidence/verifier/alice-example-org.json`).
Template and field meanings: [`evidence/verifier/TEMPLATE.md`](verifier/TEMPLATE.md).

Don't have a challenge? Ask for one in a public issue (title: *"verifier challenge request"*) — one challenge per
party, minted fresh. Your standing as a **distinct** verifier comes from that out-of-band issuance, not from the
file.

**What a valid attestation proves, stated precisely (D-024):** a party holding your key performed AINRA
verification on inputs they could not have precomputed. It does **not** prove you ran our exact binary — a
conformant reimplementation passes too, and that is fine — and it is not a proof of personhood.

**Flip condition for the DoD row:** three or more attestations, from three separately-vetted parties, each passing
`kits/verifier/check-attestation.mjs --secret <answer-key>` against the challenge issued to that party. Current
count is published in [`ROADMAP.md`](../ROADMAP.md) and computed by `make genesis-status`.

## 2. Witness candidacies (`evidence/witness/`)

A witness cosigns log checkpoints so nobody — including us — can serve a forked history unnoticed. Run
`witnessd` (see `deploy/witness-quickstart.md`), then submit a candidacy file:

```json
{
  "candidate_id": "example-witness",
  "endpoint": "https://witness.example.org",
  "operator": "Example Institution",
  "jurisdiction": "EU",
  "contact": "public issue thread or advisory channel — no email needed",
  "production": false
}
```

CI checks the shape and **probes your endpoint**: it fetches `/info`, confirms the self-declared metadata is
present, and checks cosign capability against the staging network. The probe result is posted on the PR.

Accepted candidacies land in `witnesses/candidates.json`, **clearly marked candidate-not-production**. A witness
becomes production only through the ceremony/charter process — never by merging a file.

## 3. Custodian interest

Holding one of nine root-key shares is not a form submission; it is a conversation and, eventually, a recorded
ceremony. Read the packet — `outreach/CEREMONY-CUSTODIAN-BRIEF.md` and `docs/genesis-day/RUNBOOK.md` — then open a
public issue saying you are interested, or reach the maintainer through the private advisory channel if you would
rather not be public yet.

**Privacy:** no names, no emails, no affiliations land in this repository from that conversation. What lands here
is a **count** in `ROADMAP.md`, nothing more (D-036: the root holds no personal data, and that includes yours).

---

## For agents

`/llms.txt` and `/skills.md` describe these three paths in machine-readable form, so an agent can tell its operator
exactly what to submit and where. The runner and corpus needed to produce an attestation are public; nothing here
requires an account with us.
