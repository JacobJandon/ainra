<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Intake — how strangers hand us evidence

Several Definition-of-Done rows in `docs/DOD.md` can only be moved by people who are not us. This directory is how
their artifacts arrive: **as a pull request that verifies itself in CI.**

| You want to | Submit | CI does | The row moves when |
|---|---|---|---|
| Prove you verified AINRA independently | `evidence/verifier/<your-id>.json` | public checks (signature, shape, corpus hashes, nonce) | **≥3 distinct valid attestations**, each confirmed against the maintainer's private answer key |
| Run a witness | `evidence/witness/<candidate-id>.json` | shape check + a probe of your declared endpoint | never automatically — candidacies are candidacies |
| Show what your witness signed | `evidence/cosignatures/<name>.json` | nothing; `make genesis-status` verifies it | **≥3 distinct outside keys** cosigning one checkpoint the log signed |
| Rebuild a release yourself | `evidence/rebuild/<your-id>.json` | nothing; `make genesis-status` verifies it | one signed statement whose manifest digest matches the tag |
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

### Cosignatures (`evidence/cosignatures/`)

A candidacy is a witness offering to run. What moves the board's witness row is what a running witness **signed**:
one file per cosignature, `{ "witness_key", "checkpoint": {origin, size, root}, "checkpoint_sig", "cosignature",
"observed_at" }` — the checkpoint and its signature exactly as the registrar served them, your Ed25519 key
(base64url), and your signature over the checkpoint's canonical bytes. `make genesis-status` counts **distinct keys
over one checkpoint** that the registrar's log really signed (checked against the root-signed directory in
`evidence/anchors/`), and never a key the project runs (`witnesses/project-keys.json`). Three cosignatures from one key
are one witness. `evidence/anchors/` holds the published directory and the ceremony's root keys (`roots.json`); a
change to it changes what every cosignature is checked against, so it is reviewed as a change to the roots, never
merged as part of a submission.

## 2b. An outside rebuild (`evidence/rebuild/`)

Rebuild a tagged release on your own machine and sign what you got:

```sh
git checkout v0.6.0 && make repro
node tools/genesis-board/rebuild-statement.mjs --tag v0.6.0 --key my-rebuild.pem --keygen --builder "<who you are>"
```

Submit `rebuild-statement.json` as `evidence/rebuild/<your-id>.json`. It counts when its signature verifies, your key
is not one the project signs with, and its manifest digest equals the one computed from `MANIFEST.sha256` at that tag
(lines sorted bytewise, so your locale cannot change it). It proves your rebuild reproduced the published artifacts
byte for byte; it does not prove your toolchain is independent of ours.

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
