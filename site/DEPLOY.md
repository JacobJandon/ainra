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
| `robots.txt`, `sitemap.xml` | crawler policy + sitemap (both name `https://ainra.org` — find-replace to your domain) |
| `site.webmanifest`, `icon-192.png`, `icon-512.png`, `apple-touch-icon.png` | installable/PWA metadata + home-screen icons |
| `og-cover.png` | 1200×630 social-share image referenced by the Open Graph / Twitter tags |

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

Every page already ships full head furniture — `<link rel="canonical">`, Open Graph + Twitter-card meta, JSON-LD
(`Organization` + `WebSite`), `apple-touch-icon`, and a web manifest — plus a `sitemap.xml`, `robots.txt`, and a real
1200×630 `og-cover.png` for social unfurls. The favicon is an inline SVG data-URI on every page (self-contained).

**The one launch edit:** all of these reference the canonical host `https://ainra.org`. If you publish under a different
domain, find-replace `ainra.org` across `*.html`, `sitemap.xml`, and `robots.txt` (and `start_url`/`scope` in
`site.webmanifest` if you serve from a sub-path). That is the whole SEO/social wiring — nothing else to add.

## Response headers (set these on your static host)

The site needs no special headers to function, but a public deploy should set:

- `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'self'; frame-ancestors 'none'` — page styles and the small reveal/demo scripts are inline, so `'unsafe-inline'` is required; there is no `connect-src` to any third party (the demo never phones home).
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=63072000` (once served over HTTPS)

## Don't publish these

`README.md` and `DEPLOY.md` are developer docs — exclude them from the published output (they're not linked from any
page). Never publish `data/registrar-*` (registrar key-seed material — `make site-demo` strips it and it is not
committed). Everything else in `site/` is meant to be public.

Nothing about the demo changes when you go live — it never called home in the first place.
