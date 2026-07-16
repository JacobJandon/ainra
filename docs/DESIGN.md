<!-- SPDX-License-Identifier: CC0-1.0 -->
# DESIGN — the AINRA visual system

Extracted verbatim from the launch landing page (`apps/landing/index.html`, the v12 design) so every AINRA
surface — docs site, console, registrar box, the passport card renderer — shares one identity. Tokens below are
the source of truth; do not invent new colors or fonts.

## Brand

- **Name:** AINRA — *Agent Identity and Naming Registry Authority*.
- **One-liner (title tag):** "AINRA — The identity layer for autonomous AI."
- **Positioning line:** "AINRA is its neutral root: an open standard." Neutral root, never an issuer, never a scorer
  (mirrors Charter S / MTS structural separation).
- **Voice:** plain, infrastructural, non-hype. No marketing clichés (no "free / risk-free / trusted by"). It
  *demonstrates* (a playable `ainra verify …` CLI line, real passport render) rather than *claims*.

## Logo — the AINRA sigil (ouroboros + orbit)

An ouroboros arc (a ring that returns on itself, with a small arrowhead "head") wrapping a concentric orbit/eye
motif, cut by a single green quarter-arc accent. It reads as *a closed loop of identity that verifies itself*.
Two variants ship as SVG `<symbol>`s (never emoji, per house rule): `#ainra-sigil` (on light) and `#ainra-sigil-lt`
(on dark). Canonical viewBox `0 0 112 112`. Dark-on-light source:

```svg
<g id="ainra-sigil">
  <path d="M 98.4 33.5 A 48 48 0 1 0 78.5 13.6" fill="none" stroke="#0B1220" stroke-width="3" stroke-linecap="round"/>
  <path d="M 95.8 29.2 L 98.7 27.2 M 91.7 23.9 L 94.3 21.5 M 86.9 19.2 L 89.1 16.6" stroke="#0B1220" stroke-width="1" opacity=".5"/>
  <path d="M 80.6 11.5 L 83.4 18.5 L 76.4 15.7 Z" fill="#0B1220"/>          <!-- arrowhead / ouroboros head -->
  <circle cx="79.6" cy="14.2" r="1.1" fill="#F5F6F3"/>                       <!-- eye highlight -->
  <circle cx="56" cy="56" r="36" stroke="#0B1220" stroke-width="1.2" fill="none"/>
  <circle cx="56" cy="56" r="26" stroke="#0B1220" stroke-width="1.6" fill="none"/>
  <ellipse cx="56" cy="56" rx="11" ry="26" stroke="#0B1220" stroke-width="1" fill="none"/>  <!-- orbit -->
  <line x1="30" y1="56" x2="82" y2="56" stroke="#0B1220" stroke-width="1.1"/>
  <path d="M33.5 43 h45 M33.5 69 h45" stroke="#0B1220" stroke-width="0.8" opacity="0.6"/>
  <path d="M56 30 a26 26 0 0 1 26 26" stroke="#1A6B4E" stroke-width="3" stroke-linecap="round" fill="none"/>  <!-- green accent -->
  <circle cx="56" cy="56" r="2.4" fill="#0B1220"/>
</g>
```

The light-on-dark variant (`#ainra-sigil-lt`) swaps ink `#0B1220`→`#E7EAF0` and the accent `#1A6B4E`→`#57C08F`.

## Color tokens

| Token | Value | Use |
|---|---|---|
| `--green` | `#1A6B4E` | primary brand green (accent arc, primary actions, VALID) |
| `--green-br` | `#57C08F` | bright green (on dark, hovers, highlights) |
| `--ink` | `#0B1220` | primary text / dark surfaces |
| `--paper` | `#F5F6F3` | page background (warm off-white) |
| `--card` | `#FFFFFF` | card surface |
| `--line` | `#E2E5DF` | hairline borders / dividers |
| `--muted` | `#5A6372` | secondary text |

Dark-surface ramp (hero, passport back, code): `#000002`, `#0B1220`, `#111B30`, `#1d2a44`. Cool neutrals for
strokes/labels on dark: `#8B94A6`, `#98A1B3`, `#B9C1CF`, `#C6CDDA`, `#D7DCE5`, `#E7EAF0`.

Semantic mapping for the verifier UI: **VALID → `--green`**; **INVALID → ink/muted with the machine reason string**
shown as mono text (never a scary red flood — INVALID is a normal, information-bearing outcome).

## Typography

| Role | Stack |
|---|---|
| Display (`--display`) | `'Bricolage Grotesque', 'Inter', sans-serif` |
| Body (`--body`) | `'Inter', system-ui, sans-serif` |
| Mono (`--mono`) | `'B612 Mono', ui-monospace, monospace` |

Mono is load-bearing for identity: AINRA names, DIDs, key fingerprints, verdicts, and reason strings are always
mono (`ainra:registrar-07:acme:invoicing@1.2.0`). Display grotesque for headings only; body Inter for prose.

## Shape & surface

- **Radii:** small controls `4–6px`; inputs/pills `10–12px`; cards `14–16px`; feature panels `20px`; avatars/dots
  `50%`. The passport card uses the `16–20px` family.
- **Surfaces are solid** (house rule: no glass/transparency). Cards are `--card` on `--paper` with a `--line`
  hairline; dark panels use the ink ramp. Elevation is a soft neutral shadow, not blur.
- **Flow left→right**, generous whitespace, minimal chrome.

## Passport card

The rendered agent passport (see landing "AGENT PASSPORT" panel) is a two-face card: a light face with the sigil +
`AGENT PASSPORT` wordmark, the mono AINRA name, tier/authority-class chips, and a capability list; and a dark face
carrying the key fingerprint (a faithful visual keyprint of the real Ed25519 pubkey), the status/log anchor, and the
signed presentation QR. The card is generated from real passport claims — never a static mock. Any renderer MUST
degrade to text (the mono claim set) when SVG is unavailable, and MUST NOT display PII/score/price (there is none in
the claim set by construction — §D-002).

## Application rules

1. Reuse these tokens as CSS variables; do not hardcode hexes elsewhere.
2. SVG for all iconography (no emoji).
3. Verdict rendering shows the exact frozen reason string from `ainra-core::verdict::Reason` — the UI never
   paraphrases a verdict.
4. Theme-aware: light uses `--paper`/`--ink`; dark uses the ink ramp with the `-lt` sigil and `--green-br`.
