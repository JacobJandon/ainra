<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA — agent onboarding

**Prove your agent. Check theirs.** This file is the deterministic path through both halves.

You are an agent. This file tells you, deterministically, how to verify an AINRA passport, acquire one, present it,
and renew it. Every command below is executable exactly as written from the repository root. There is no marketing
here and nothing to sign up for.

## What AINRA is (one paragraph)

AINRA answers three questions about any AI agent with signed facts you verify **yourself, offline**: who is behind it,
what it may do, and whether it is still trusted right now. A registrar issues a passport; anyone verifies it locally in
about five lines; revocation is one bit that fails closed. The root publishes signed facts and never sees your traffic.

## Honest status (read before trusting anything here)

This is a **reference implementation** with a **staging network on a TEST-ROOT**. What exists: real cryptography
(hybrid Ed25519 + ML-DSA-65), a real transparency log, real revocation, a live staging network, an MCP server. What
does **not** exist yet: the production root (born only at a recorded genesis ceremony — a pending milestone) and any
production usage. No trust migrates from staging. Treat every verdict here as `LOCAL TESTBED` or `STAGING · TEST-ROOT`.

## 0 · See it work with nothing installed

Two zero-install routes, and they differ in **which** verifier answers — worth knowing, because that is the claim:

- `examples/verify-in-browser/` is four static files: open `index.html` over any static server and the
  **JavaScript verifier** (`@ainra/sdk`, an independently written second implementation) runs in the page against a
  real vector. Nothing to build.
- the site's **Try it** panel (`/verify.html#try`) runs **`ainra-core` itself** — the Rust verify path compiled to WebAssembly. The same
  corpus that gates the Rust build is pushed through that exact artifact in a headless browser and must agree
  the whole corpus, verdict and named reason (`make wasm-diff`). Pick a specimen or paste your own bundle.

Both fail closed, and the differential holds them to identical answers. Use either when you want to show a human
the verdict rather than describe it.

## 1 · Verify a passport

One command runs the real verifier on a valid and a revoked credential and prints the verdict plus the named-reason
legend. No account, no server:

```bash
make verify
```

To verify in your own code instead, it is ~5 lines with `@ainra/sdk`:

```bash
node --input-type=module -e '
import { Verifier } from "./packages/sdk-ts/dist/index.js";
import { readFileSync } from "node:fs";
const j = (f) => JSON.parse(readFileSync("kits/verifier/sample-artifacts/" + f, "utf8"));
const roots = j("roots.json");
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);
const verdict = verifier.verify(j("bundle-valid.json"), j("meta.json").now);
console.log("verdict:", JSON.stringify(verdict));
'
```

## 2 · Acquire a passport (a registrar's public door)

Issuance happens at a registrar, never at the root. One command boots a local registrar and issues your first
passport, leaving the registrar in `./my-registrar` for reuse:

```bash
make issue-first
```

Against a live network you control, an accredited registrar exposes the same door over HTTP (`POST /issue` with the
operator's write token) — see `docs/quickstarts/cli.md`.

## 3 · Present it

Put the presentation bundle in one request header — `x-ainra-passport`, as base64url of its canonical JSON (full spec
in `docs/PRESENTATION.md`). This builds the header value from a bundle and confirms it is non-empty:

```bash
node -e '
const fs = require("node:fs");
const bundle = fs.readFileSync("kits/verifier/sample-artifacts/bundle-valid.json");
const header = Buffer.from(bundle).toString("base64url");
if (!header.length) { console.error("empty header"); process.exit(1); }
console.log("x-ainra-passport: " + header.slice(0, 48) + "…  (" + header.length + " bytes)");
'
```

Any AINRA-aware surface then emits one verdict event shape:
`{status, reason, name, number, tier, freshness_age_s, instance_iid, instance_exp}`.
The last two are `null` unless you present as a running copy — see §3b.

## 3b · Present as a running copy (ADR-019)

If you are one running instance of an agent rather than the agent's owner, you should **not** hold the lineage's
key. Your operator mints you a credential that expires in minutes, is narrower than the passport, and is bound to a
key only you hold. You get two files and nothing else; the passport key stays on the minting side.

```bash
ainra_bin=./apps/cli-node/bin/ainra.js
export AINRA_HOME="$(mktemp -d)/.ainra"
node "$ainra_bin" init >/dev/null && node "$ainra_bin" accredit reg-eu-1 >/dev/null
node "$ainra_bin" issue "ainra:reg-eu-1:acme:billing@1.0.0" >/dev/null
# the OPERATOR mints, where the passport key lives:
node "$ainra_bin" instance issue "ainra:reg-eu-1:acme:billing@1.0.0" \
  --aud https://api.example --caps read:invoices --ttl 900
# the RUNNING COPY presents; a receiving service checks it:
iid=$(ls "$AINRA_HOME"/passports/*.instance.json | head -1 | xargs basename | sed 's/\.instance\.json//')
node "$ainra_bin" instance verify "$iid" --aud https://api.example
```

Two rules you cannot talk your way around:

- **The audience is the receiver's, not yours.** Present to a service you were not addressed to and you get
  `instance_pop_invalid`. A verifier that has not been told who it is accepts no instance credential at all.
- **Your credential dies with the passport.** If the lineage is revoked you are refused with `revoked` — not an
  instance reason — because the lineage failed, not you.

## 4 · Renew

Identity is permanent; the credential is bounded (366 days) and renews with continuity (ADR-017). Preview a renewal
without mutating anything:

```bash
ainra_bin=./target/release/ainra
[ -x "$ainra_bin" ] || cargo build --release -q -p ainra-cli-rs
"$ainra_bin" renew my-registrar ainra:registrar-07:acme:assistant@1.0.0 --version 1.0.1 --dry-run
```

## Native tools (MCP)

If you speak MCP, you do not need the shell — connect the `@ainra/mcp` server and call `ainra_verify`, `ainra_lookup`,
`ainra_status` (read-only) and `ainra_issue` / `ainra_renew` / `ainra_revoke` (write, `confirm: true` required). See
`docs/quickstarts/mcp.md`.

## 5 · Submit evidence (help the root reach genesis)

If your operator wants to help AINRA cross its three remaining real-world milestones, each submission is a
self-verifying pull request. Full flow and the exact flip conditions: [`evidence/README.md`](https://github.com/JacobJandon/ainra/blob/main/evidence/README.md).

- **Prove independent verification.** Get a fresh challenge, then:
  ```sh
  make verify-as-external CHALLENGE=/path/to/challenge   # writes verifier-attestation.json
  node tools/intake-check.mjs verifier-attestation.json  # the public checks CI will run
  ```
  Add it as `evidence/verifier/<id>.json` in a PR. Counts only after the maintainer confirms execution against a
  private answer key; the DoD row moves at 3 distinct valid attestations. Never auto-flipped.
- **Offer a witness.** Run `witnessd` (`deploy/witness-quickstart.md`), add `evidence/witness/<id>.json`; CI probes
  the endpoint. Candidate, not production.
- **Custodian interest** is a conversation, not a file — read `outreach/CEREMONY-CUSTODIAN-BRIEF.md`.

## Verify this file works

Every step above is replayed end to end in CI:

```bash
make skills-replay
```
