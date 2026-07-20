<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Mirroring AINRA — the root can be dark, mirrors are enough

The entire public surface (docs/ARTIFACT-CONTRACT.md) is static files. Anyone can mirror all of it and any verifier
can point at any mirror — the transparency guarantee travels with the **content**, not the channel. The root
operating the log can go offline and every verifier keeps working from mirrors, because a checkpoint is
root/delegate-**signed** and an inclusion proof is checked against it with local hashing.

## Mirror the whole surface

```sh
# HTTP (any static host): recursively pull the public tree
wget -r -np -nH --cut-dirs=0 http://<origin>:8091/ -P ./ainra-mirror
# or rsync if the origin exposes it
rsync -a --delete rsync://<origin>/ainra-public/ ./ainra-mirror/
```

Serve the mirror with the SAME contract headers (docs/ARTIFACT-CONTRACT.md):

```sh
node tools/artifact-server.mjs ./ainra-mirror 8091     # the reference server already sets CORS/cache/ETag/banner
# or any CDN/static host with: CORS *, immutable cache on */checkpoints/* and */tiles/*, short-cache+ETag elsewhere
```

## Point a verifier at any mirror

- **AINRAscan:** open `…/ainrascan/?net=http://<mirror>:8091` — it fetches `/registry.json` from the mirror and
  verifies every proof in the browser. Nothing else changes.
- **The SDK / a custom verifier:** fetch `/directory.json` (anchors) + `/registrars/<id>/{export,status/current}.json`
  from the mirror and run `@ainra/sdk`. The verdict is identical regardless of which mirror served the bytes — a
  mismatch is impossible without breaking a signature, which is the point.
- **Integrity of a mirror:** `make verify-mirror MIRROR=<dir>` byte-verifies a mirror against the signed manifest
  (fail-closed on tamper/missing/extra) — the same machinery that guards the CC0 artifact set.

## Why this is the scale story

Because verification consults only signed static files and never the root, a mirror is a plain CDN edge. Global
scale is adding edges — a configuration, not a protocol change. See `docs/SCALE.md` for the measured numbers.
Nothing here implies usage: mirrors serve the truth; whether anyone reads it is earned by the humans running the
pending DoD rows.
