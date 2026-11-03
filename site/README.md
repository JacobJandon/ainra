<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# site/ — the public AINRA website

The static front door for AINRA: the landing page, the Standard, a verify walkthrough, the Foundations/charter page, an
honest status page, an in-browser demo that runs the real verifier, and a 404. Plain HTML/CSS with a little vanilla JS —
**no framework, no build step for the pages themselves.**

## Build & serve

```sh
make site            # refresh the two derived downloads from canonical sources
make site SERVE=1    # …and serve at http://127.0.0.1:8088  (PORT=… to change)
```

The pages (`site/*.html` — among them `index`, `standard`, `verify`, `status`, `demo`, `docs`, `404`) are committed and self-contained.
`make site` only regenerates the two **download artifacts** so they can never go stale:
- `ainra-cli-v<version>.zip` ← packaged from **`apps/cli-node/`** (the real reference CLI).
- `AINRA_I_The_Standard.md` ← copied from **`docs/AINRA_I_The_Standard.md`** (the canonical Standard).

Both are gitignored (derived, not committed) — one source of truth each, so the site's download is always the current,
real thing. The live site deploys through `bash tools/export-site.sh`, which runs `make site` and pushes `site/` to
a separate static-site repository that the host deploys; pushing this repository does not change the live site.
(`.github/workflows/pages.yml` can publish `site/` to GitHub Pages instead; it is not how ainra.org is served.)

## Nothing phones home

Every page is self-contained apart from ONE embedded video on the landing (§watch, a direct embed that loads from
its host): no CDN, no web fonts, no external scripts, no other external images (all other graphics are
inline SVG), no analytics, no fetch calls. That was deliberate — a site for a neutral root whose pitch is *verify,
don't trust* should not leak its visitors to third parties — and the video is a deliberate exception, made with
eyes open: it was first shipped as a click-to-load facade that loaded nothing until a visitor pressed play, but
that facade failed to play reliably, and a section nobody can watch argues nothing. The rest of the site keeps the
property; the §watch section does not, and this file says so rather than letting the old claim stand. Typography uses a
system-font stack (the design names `Bricolage Grotesque` / `Inter` / `B612 Mono` first and degrades gracefully to
`system-ui` / `ui-monospace` if they aren't installed locally). The S7 neutrality lint scans these pages, so no
commercial third-party name can slip into them.

## Honesty

`status.html` states only what exists and is meant to track the same reality as `make genesis-status` (today:
pre-ceremony, logs sealed 0, recruiting). If a page ever claims something that isn't true, that's a bug — fix the page,
not the truth.
