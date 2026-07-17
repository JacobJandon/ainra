<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# site/ — the public AINRA website

The static front door for AINRA: the landing page, the Standard, a verify walkthrough, the honest status page, and the
"get involved" recruitment pages (external verifiers, witnesses, custodians). Plain HTML/CSS with a little vanilla JS —
**no framework, no build step for the pages themselves.**

## Build & serve

```sh
make site            # refresh the two derived downloads from canonical sources
make site SERVE=1    # …and serve at http://127.0.0.1:8088  (PORT=… to change)
```

The 8 pages are committed and self-contained. `make site` only regenerates the two **download artifacts** so they can
never go stale:
- `ainra-cli-v0.1.0.zip` ← packaged from **`apps/cli-node/`** (the real reference CLI).
- `AINRA_I_The_Standard.md` ← copied from **`docs/AINRA_I_The_Standard.md`** (the canonical Standard).

Both are gitignored (derived, not committed) — one source of truth each, so the site's download is always the current,
real thing. To deploy statically, run `make site` then publish the `site/` directory (the GitHub Pages workflow does
exactly this: see `.github/workflows/pages.yml`).

## Nothing phones home

Every page is **fully self-contained**: no CDN, no web fonts, no external scripts, no external images (all graphics are
inline SVG), no analytics, no fetch calls. This is deliberate — a site for a neutral root whose whole pitch is *verify,
don't trust; nothing phones home* must not itself leak every visitor to a third party. Typography uses a
system-font stack (the design names `Bricolage Grotesque` / `Inter` / `B612 Mono` first and degrades gracefully to
`system-ui` / `ui-monospace` if they aren't installed locally). The S7 neutrality lint scans these pages, so no
commercial third-party name can slip into them.

## Honesty

`status.html` states only what exists and is meant to track the same reality as `make genesis-status` (today:
pre-ceremony, logs sealed 0, recruiting). If a page ever claims something that isn't true, that's a bug — fix the page,
not the truth.
