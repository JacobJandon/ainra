<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Deploying the AINRA site

The whole `site/` folder is **static and fully self-contained** — no build step, no CDN, no web fonts, no telemetry,
no backend. Every page (including the in-browser demo) works from a plain file server. That makes it deployable to any
static host in one step.

## What's in the folder

| File(s) | Purpose |
|---|---|
| `index.html` … `status.html` | the five content pages |
| `demo.html` | **the live demo** — verifies a real passport in the visitor's browser |
| `404.html` | on-brand not-found page |
| `vendor/ainra-sdk.js` | the real `@ainra/sdk` verifier, bundled for the browser (the demo's engine) |
| `data/registry.json` | a real, core-verified seeded registry the demo reads |
| `AINRA_I_The_Standard.md`, `ainra-cli-v0.1.0.zip` | downloadable assets |
| `robots.txt` | crawler policy |

`vendor/ainra-sdk.js` and `data/registry.json` are derived; regenerate with **`make site-demo`** from the repo root.

## Test it locally

```sh
cd site && python3 -m http.server 8080
# open http://localhost:8080/  →  "Try it live"
```

## Publish (pick one — all zero-config for a static folder)

- **Any static host / object storage + CDN:** upload the `site/` folder; set `404.html` as the error document; done.
- **Git-based static hosting:** point the provider at this repo, set the publish directory to `site/`, no build command.
- **Your own server:** `rsync -a site/ user@host:/var/www/ainra/` behind nginx/Caddy serving static files.

Set the error page to `404.html`. No environment variables, no secrets, no database.

## The one thing that needs "connecting" for launch

Everything is client-side **except capturing founding-table signups**. Today the form is deliberately browser-local
(it says so honestly — nothing is sent). To collect real signups at launch, wire the `#ctaForm` submit in `index.html`
to one of:

1. a **`mailto:` fallback** (zero infrastructure) — prefill a message to your intake address; or
2. a **serverless function / form endpoint** you control — `POST {seat, email}` to it on submit.

Keep the honest success copy accurate to whichever you choose. Until then the browser-local behavior is correct and truthful.

## Before pointing a real domain at it

- Add `<link rel="canonical">` + Open Graph / Twitter-card meta to each `<head>` (they're intentionally absent now — no
  real URLs exist yet). A one-line `og:image` can reuse the sigil.
- Add a `sitemap.xml` once the domain is known and reference it from `robots.txt`.
- The favicon is already an inline SVG data-URI on every page (self-contained).

Nothing about the demo changes when you go live — it never called home in the first place.
