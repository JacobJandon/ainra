// SPDX-License-Identifier: Apache-2.0 OR MIT
// Renders ainra/samples/data/sample-*.json (real signed credentials + a REAL computed verdict, from the
// `sample_passport` example in ainra-core) into passport-card SVGs that follow the v12 landing page's design
// EXACTLY: the same sigil markup (extracted live from apps/landing/index.html, never hand-copied), the same color
// tokens, the same card anatomy (numbered fields, dashed data rows, MRZ zone, verify line) — see docs/DESIGN.md.
//
// Every value on the card is read from the sample's real claims (or derived from the real Ed25519 public key, for
// the fingerprint + portrait identicon). Nothing is invented; every card is labeled SPECIMEN, matching the landing
// page's own convention for its demo card.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const LANDING = path.join(ROOT, "apps/landing/index.html");
// Input/output dirs are overridable (M7 `make repro` builds the artifact set into a fresh temp tree, so the
// reproducibility proof is NON-destructive and compares a clean rebuild against the committed files).
const DATA_DIR = process.env.AINRA_SAMPLES_DATA || path.join(ROOT, "samples/data");
const OUT_DIR = process.env.AINRA_SAMPLES_OUT || path.join(ROOT, "samples");
fs.mkdirSync(OUT_DIR, { recursive: true });

// ── Design tokens (docs/DESIGN.md — the single source; do not hardcode a different palette) ─────────────────────
const T = {
  green: "#1A6B4E",
  greenBr: "#57C08F",
  ink: "#0B1220",
  red: "#B23A3A",
  paper: "#F5F6F3",
  card: "#FFFFFF",
  line: "#E2E5DF",
  muted: "#5A6372",
  display: "'Bricolage Grotesque','Inter',sans-serif",
  mono: "'B612 Mono',ui-monospace,monospace",
};

// ── Extract the real sigil markup from the landing page (never hand-transcribed) ─────────────────────────────────
function extractSigilDefs() {
  const html = fs.readFileSync(LANDING, "utf8");
  const m = html.match(/<svg width="0" height="0"[\s\S]*?<\/svg>/);
  if (!m) throw new Error("could not find the sigil <defs> block in apps/landing/index.html");
  return m[0];
}

function b64uDecode(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

// ── The DATA GLYPH — a 7×7 dot grid that ENCODES the passport, so the dots actually mean something. Each of the
// top five rows is a fact read as a left-anchored bar; the bottom two rows are the true key-bit fingerprint. Change
// any fact and the picture changes; a reader with the legend can decode tier/authority/capabilities/status by eye.
const GLYPH_ROWS = ["T", "A", "C", "H", "S", "K", "K"]; // Tier · Auth · Caps · Headroom · Status · Key(print)

// Build the 7×7 cell matrix from the real passport claims + the key fingerprint. Returns rows of {n, color} bars
// for the fact rows and raw on/off for the two key rows.
function glyphCells(claims, fpHex, isValid) {
  const tierNum = Math.max(0, "L0 L1 L2 L3 L4".split(" ").indexOf(claims.tier || "L0")); // 0..4
  const authNum = Math.max(1, parseInt(String(claims.authority?.class || "A1").replace(/\D/g, ""), 10) || 1); // 1..4
  const caps = (claims.capabilities || []).length;
  const ceil = (claims.scope_ceiling || []).length;
  const headroom = Math.max(0, ceil - caps); // delegable slack: how much authority can still be narrowed downstream
  const clamp = (n) => Math.max(0, Math.min(7, n));

  const rows = [];
  rows.push({ kind: "bar", n: clamp(tierNum + 1), color: T.green }); // r0 TIER  (L0→1 … L4→5 green)
  rows.push({ kind: "bar", n: clamp(authNum), color: T.ink }); //       r1 AUTH  (A1→1 … A4→4 ink)
  rows.push({ kind: "bar", n: clamp(caps), color: T.green }); //         r2 CAPS  (granted capability count)
  rows.push({ kind: "bar", n: clamp(headroom), color: T.ink }); //      r3 HEADROOM (ceiling − caps, delegable slack)
  rows.push({ kind: "status", ok: isValid }); //                        r4 STATUS (full green = valid, full red = revoked)
  // r5,r6 KEY: 14 bits from the sha256(pubkey) fingerprint — a faithful visual fingerprint of the real key.
  const keyInt = parseInt(fpHex.slice(0, 4), 16); // 16 bits, use 14
  for (let kr = 0; kr < 2; kr++) {
    const bits = [];
    for (let c = 0; c < 7; c++) bits.push(((keyInt >> (kr * 7 + c)) & 1) === 1);
    rows.push({ kind: "key", bits });
  }
  return rows;
}

// A one-line human decode of the glyph, printed as the caption's second line ("the dots mean something you know").
function glyphLegend(claims, isValid) {
  return `${claims.tier || "L?"} ${DOT} ${claims.authority?.class || "A?"} ${DOT} ${(claims.capabilities || []).length}CAP ${DOT} ${isValid ? "VALID" : "REVOKED"}`;
}

function portraitSvg(x, y, size, claims, fpHex, isValid) {
  const rows = glyphCells(claims, fpHex, isValid);
  const gutter = size * 0.13; // left strip for the row labels (T A C H S K K)
  const pad = size * 0.07;
  const inner = size - pad * 2 - gutter;
  const gap = inner * 0.03;
  const cell = (inner - gap * 6) / 7;
  const gridX = x + pad + gutter;

  let g = `<rect x="${x}" y="${y}" width="${size}" height="${size}" rx="8" fill="${T.paper}" stroke="${T.line}"/>`;
  for (let r = 0; r < 7; r++) {
    const row = rows[r];
    const cy = y + pad + r * (cell + gap);
    // row label
    g += `<text x="${(x + pad + gutter * 0.42).toFixed(1)}" y="${(cy + cell * 0.78).toFixed(1)}" text-anchor="middle" font-family="${T.mono}" font-size="${(cell * 0.6).toFixed(1)}" fill="${T.muted}">${GLYPH_ROWS[r]}</text>`;
    for (let c = 0; c < 7; c++) {
      let fill = null;
      if (row.kind === "bar") fill = c < row.n ? row.color : null;
      else if (row.kind === "status") fill = row.ok ? T.green : T.red;
      else if (row.kind === "key") fill = row.bits[c] ? T.ink : null;
      const cx = gridX + c * (cell + gap);
      if (fill) {
        g += `<rect x="${cx.toFixed(1)}" y="${cy.toFixed(1)}" width="${cell.toFixed(1)}" height="${cell.toFixed(1)}" rx="1.5" fill="${fill}"/>`;
      } else {
        // empty slot: a faint dot so the grid reads as a grid, not scattered marks
        g += `<circle cx="${(cx + cell / 2).toFixed(1)}" cy="${(cy + cell / 2).toFixed(1)}" r="${(cell * 0.09).toFixed(1)}" fill="${T.line}"/>`;
      }
    }
  }
  g += `<text x="${x + size / 2}" y="${y + size + 12}" text-anchor="middle" font-family="${T.mono}" font-size="7" letter-spacing="1.5" fill="${T.muted}">DATA GLYPH</text>`;
  g += `<text x="${x + size / 2}" y="${y + size + 23}" text-anchor="middle" font-family="${T.mono}" font-size="7.5" letter-spacing="0.6" fill="${isValid ? T.green : T.red}">${esc(glyphLegend(claims, isValid))}</text>`;
  return g;
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function dateStr(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  const months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
  return `${String(d.getUTCDate()).padStart(2, "0")} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}
function yymmdd(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  return `${String(d.getUTCFullYear()).slice(2)}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
}

function mrzPad(s, n) {
  return (s.toUpperCase().replace(/[^A-Z0-9<]/g, (c) => (c === " " ? "<" : "")) + "<".repeat(n)).slice(0, n);
}

// Parses `ainra:{registrar}:{operator}:{lineage}@{version}`.
function parseSub(sub) {
  const [name, version] = sub.split("@");
  const [, registrar, operator, lineage] = name.split(":");
  return { registrar, operator, lineage, version };
}

function fingerprintHex(pubkeyBytes) {
  return crypto.createHash("sha256").update(pubkeyBytes).digest("hex");
}
function fingerprintDisplay(hex) {
  const h = hex.slice(0, 16).toUpperCase();
  return h.match(/.{1,4}/g).join(":");
}

const DOT = "·"; // literal middle-dot char — NOT the &#183; entity (esc() would double-escape its '&')

function renderCard(sample, sigilDefs) {
  const claims = JSON.parse(sample.claims);
  const { registrar, operator, lineage, version } = parseSub(claims.sub);
  const pubBytes = b64uDecode(claims.keys[0].ed25519); // the AGENT's own key — real holder key, real fingerprint
  const fpHex = fingerprintHex(pubBytes);
  const fpDisplay = fingerprintDisplay(fpHex);
  const docCode = fpHex.slice(0, 3).toUpperCase() + "-" + fpHex.slice(3, 6).toUpperCase();
  const verdict = sample.verdict;
  const isValid = verdict.verdict === "valid";

  // Wide landscape ID card — 880×560, the proportions of the original AINRA passport data page.
  const W = 880,
    H = 560;
  const M = 30;
  const parts = [];
  const body = [];

  // ── header band ──
  const headH = 56;
  body.push(`<line x1="0" y1="${headH}" x2="${W}" y2="${headH}" stroke="${T.line}"/>`);
  body.push(
    `<svg x="${M}" y="12" width="34" height="34" viewBox="0 0 112 112"><use href="#ainra-sigil"/></svg>` +
      `<text x="${M + 44}" y="28" font-weight="700" font-size="13" letter-spacing="2" fill="${T.ink}">AGENT PASSPORT</text>` +
      `<text x="${M + 44}" y="43" font-size="8.5" letter-spacing="1.4" fill="${T.muted}">VERIFIABLE AGENT IDENTITY</text>`,
  );
  body.push(
    `<text x="${W - M}" y="26" text-anchor="end" font-size="10.5" letter-spacing="1.2" fill="${T.muted}">TYPE AP ${DOT} DOC AP-${docCode}</text>` +
      `<text x="${W - M}" y="43" text-anchor="end" font-size="9" letter-spacing="2" fill="${T.green}">SPECIMEN</text>`,
  );

  // ── left column: portrait + keyprint ── right column: numbered fields (2 cols) ──
  const bodyTop = headH + 26;
  const portraitSize = 168;
  body.push(portraitSvg(M, bodyTop, portraitSize, claims, fpHex, isValid));
  const fx = M + portraitSize + 40;
  const fields = [
    ["① LINEAGE", esc(lineage), false],
    ["② VERSION", esc(version), false],
    ["③ OPERATOR", esc(operator), false],
    ["④ REGISTRAR", esc(registrar), false],
    ["⑤ AUTHORITY", `${esc(claims.authority.class)} ${DOT} PROOF ${esc(claims.authority.principal_proof.slice(0, 8).toUpperCase())}`, false],
    ["⑥ ASSURANCE", null, true],
  ];
  const fieldRowH = 58;
  const colW = (W - M - fx) / 2;
  fields.forEach(([label, value, isChip], i) => {
    const col = i % 2,
      row = Math.floor(i / 2);
    const cx = fx + col * colW;
    const cy = bodyTop + row * fieldRowH;
    body.push(`<text x="${cx}" y="${cy + 10}" font-size="9.5" letter-spacing="1.4" fill="${T.muted}">${label}</text>`);
    if (isChip) {
      const chipText = `${claims.tier} ${DOT} ANCHORED`;
      const chipW = chipText.length * 8.4 + 22;
      body.push(
        `<rect x="${cx}" y="${cy + 18}" width="${chipW.toFixed(0)}" height="26" rx="6" fill="none" stroke="${T.green}" stroke-width="1.6"/>` +
          `<text x="${cx + 11}" y="${cy + 36}" font-size="13" font-weight="700" letter-spacing="0.6" fill="${T.green}">${esc(chipText)}</text>`,
      );
    } else {
      body.push(
        `<text x="${cx}" y="${cy + 38}" font-size="19" font-weight="600" letter-spacing="-0.3" fill="${T.ink}" font-family="Inter,${T.display}">${value}</text>`,
      );
    }
  });

  // ── datarows (full width) ──
  let y = bodyTop + portraitSize + 34;
  body.push(`<line x1="${M}" y1="${y}" x2="${W - M}" y2="${y}" stroke="${T.line}" stroke-dasharray="2 3"/>`);
  const rows = [
    ["NAME", claims.sub],
    ["VALIDITY", `ISSUED ${dateStr(claims.nbf)} ${DOT} EXPIRES ${dateStr(claims.exp)} ${DOT} RENEWABLE`],
    ["KEY", `ED25519 + ML-DSA-65 ${DOT} FP ${fpDisplay}`],
  ];
  if (Array.isArray(claims.act_chain) && claims.act_chain.length > 0) {
    const shortLineage = (name) => name.split("@")[0].split(":")[3] || name;
    const path = [shortLineage(claims.act_chain[0].from), ...claims.act_chain.map((h) => shortLineage(h.to))];
    rows.push(["CHAIN", `${path.join(" → ")}  (${claims.act_chain.length} hops, dual-signed, narrowed)`]);
  }
  const rowH = 21;
  rows.forEach(([label, value], i) => {
    const ry = y + 24 + i * rowH;
    body.push(
      `<text x="${M}" y="${ry}" font-size="9.5" letter-spacing="1.2" fill="${T.muted}">${label}</text>` +
        `<text x="${M + 110}" y="${ry}" font-size="11" letter-spacing="0.4" fill="${T.ink}">${esc(value)}</text>`,
    );
  });

  // ── issuing authority + MRZ band (bottom) ──
  body.push(
    `<text x="${M}" y="${H - 118}" font-size="9" letter-spacing="1.4" fill="${T.muted}">⑦ ISSUING AUTHORITY</text>` +
      `<text x="${M}" y="${H - 102}" font-size="11.5" letter-spacing="1" font-weight="700" fill="${T.ink}">AINRA — AGENT IDENTITY &amp; NAMING REGISTRY AUTHORITY</text>`,
  );
  const mrzTop = H - 92;
  body.push(
    `<rect x="${M - 8}" y="${mrzTop}" width="${W - 2 * (M - 8)}" height="80" rx="9" fill="${T.paper}" stroke="${T.line}"/>`,
  );
  const l1 = mrzPad(`P<AINRA${operator}<<${lineage}`, 44);
  const l2 = mrzPad(
    `${docCode.replace("-", "")}${claims.tier}${registrar}${yymmdd(claims.exp)}${claims.authority.class}<<<${isValid ? "VALID" : "REVOKED"}<<${yymmdd(claims.nbf)}`,
    44,
  );
  body.push(
    `<text x="${M + 8}" y="${mrzTop + 24}" font-size="14" letter-spacing="2.4" fill="${T.ink}">${esc(l1)}</text>` +
      `<text x="${M + 8}" y="${mrzTop + 45}" font-size="14" letter-spacing="2.4" fill="${T.ink}">${esc(l2)}</text>`,
  );
  body.push(
    `<line x1="${M + 8}" y1="${mrzTop + 55}" x2="${W - M - 8}" y2="${mrzTop + 55}" stroke="${T.line}" stroke-dasharray="2 3"/>`,
  );
  const dotColor = isValid ? T.green : T.muted;
  const verdictText = isValid ? "⑧ ROOT SIGNATURE VALID" : `⑧ INVALID ${DOT} REASON: ${verdict.reason.toUpperCase()}`;
  body.push(
    `<circle cx="${M + 14}" cy="${mrzTop + 70}" r="3.4" fill="${dotColor}"/>` +
      `<text x="${M + 26}" y="${mrzTop + 74}" font-size="10.5" letter-spacing="1.2" fill="${dotColor}">${verdictText}</text>` +
      `<text x="${W - M - 8}" y="${mrzTop + 74}" text-anchor="end" font-size="9" letter-spacing="0.6" fill="${T.muted}">LOG ${esc(sample.checkpoint.origin)} #${sample.leaf_index} ${DOT} CHECKPOINT SIZE ${sample.checkpoint.size}</text>`,
  );

  parts.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${Math.round(W * 0.8)}" height="${Math.round(H * 0.8)}" font-family="${T.mono}">`,
  );
  parts.push(sigilDefs.replace(/<svg[^>]*>|<\/svg>/g, ""));
  parts.push(`<rect x="0" y="0" width="${W}" height="${H}" rx="14" fill="${T.card}" stroke="${T.line}"/>`);
  parts.push(
    `<text x="${W / 2}" y="${H / 2 + 40}" text-anchor="middle" font-family="${T.display}" font-weight="800" font-size="150" fill="none" stroke="${T.ink}" stroke-opacity="0.04" transform="rotate(-14 ${W / 2} ${H / 2})">AINRA</text>`,
  );
  parts.push(...body);

  parts.push(`</svg>`);
  return parts.join("\n");
}

// ── Side 1: the COVER — ink-dark book front, light sigil variant, wordmark, doc number (the v0 book's cover
// reimagined in the v12 system: ink #0B1220 instead of the old black/gold, sigil-lt instead of the gold serpent).
function renderCover(sample, sigilDefs) {
  const claims = JSON.parse(sample.claims);
  const pubBytes = b64uDecode(claims.keys[0].ed25519); // the AGENT's own key — real holder key, real fingerprint
  const fpHex = fingerprintHex(pubBytes);
  const docCode = fpHex.slice(0, 3).toUpperCase() + "-" + fpHex.slice(3, 6).toUpperCase();

  const W = 880,
    H = 560;
  const p = [];
  p.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${Math.round(W * 0.8)}" height="${Math.round(H * 0.8)}" font-family="${T.mono}">`,
  );
  p.push(sigilDefs.replace(/<svg[^>]*>|<\/svg>/g, ""));
  p.push(
    `<defs><pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse">` +
      `<circle cx="2" cy="2" r="1.4" fill="${T.greenBr}" fill-opacity="0.07"/></pattern></defs>`,
  );
  p.push(`<rect x="0" y="0" width="${W}" height="${H}" rx="16" fill="${T.ink}"/>`);
  p.push(`<rect x="0" y="0" width="${W}" height="${H}" rx="16" fill="url(#dots)"/>`);
  p.push(
    `<rect x="16" y="16" width="${W - 32}" height="${H - 32}" rx="12" fill="none" stroke="#E7EAF0" stroke-opacity="0.16"/>`,
  );
  p.push(
    `<text x="${W / 2}" y="86" text-anchor="middle" font-size="12" letter-spacing="5" fill="#98A1B3">AGENT IDENTITY PASSPORT</text>`,
  );
  const sig = 174;
  p.push(
    `<svg x="${(W - sig) / 2}" y="128" width="${sig}" height="${sig}" viewBox="0 0 112 112"><use href="#ainra-sigil-lt"/></svg>`,
  );
  p.push(
    `<text x="${W / 2}" y="378" text-anchor="middle" font-family="${T.display}" font-weight="800" font-size="72" letter-spacing="3" fill="#E7EAF0">AINRA</text>`,
  );
  p.push(
    `<text x="${W / 2}" y="406" text-anchor="middle" font-size="10.5" letter-spacing="4" fill="#98A1B3">AGENT IDENTITY &amp; NAMING REGISTRY AUTHORITY</text>`,
  );
  p.push(`<line x1="300" y1="442" x2="${W - 300}" y2="442" stroke="#E7EAF0" stroke-opacity="0.18"/>`);
  p.push(
    `<text x="${W / 2}" y="474" text-anchor="middle" font-size="14" letter-spacing="3" fill="${T.greenBr}">AP-${docCode}</text>`,
  );
  p.push(
    `<text x="${W / 2}" y="500" text-anchor="middle" font-size="10" letter-spacing="2.4" fill="#98A1B3">${esc(claims.sub)}</text>`,
  );
  p.push(
    `<text x="${W / 2}" y="${H - 26}" text-anchor="middle" font-size="9" letter-spacing="4" fill="#5A6372">SPECIMEN</text>`,
  );
  p.push(`</svg>`);
  return p.join("\n");
}

// ── Side 3: ENDORSEMENTS & LOG — the v0 book's hash-chained stamps page, rebuilt over the M1 world's REAL events:
// issuance (hybrid signature), transparency-log inclusion (leaf@index under the signed checkpoint), each delegation
// hop, and revocation if present. The footer anchors the page to the real checkpoint root, the way the old page
// anchored to its CHAIN HEAD. All values come from the sample JSON; nothing is decorative fiction.
function renderStamps(sample, sigilDefs) {
  const claims = JSON.parse(sample.claims);
  const { registrar } = parseSub(claims.sub);
  const pubBytes = b64uDecode(claims.keys[0].ed25519); // the AGENT's own key — real holder key, real fingerprint
  const fpHex = fingerprintHex(pubBytes);
  const docCode = fpHex.slice(0, 3).toUpperCase() + "-" + fpHex.slice(3, 6).toUpperCase();
  const isValid = sample.verdict.verdict === "valid";
  const shortLineage = (name) => name.split("@")[0].split(":")[3] || name;

  // Build the stamp list from the sample's real events, in lifecycle order.
  const stamps = [];
  stamps.push({
    kind: "ISSUED",
    l1: `BY ${registrar.toUpperCase()}`,
    l2: `HYBRID SIGNED ${DOT} ED25519 + ML-DSA-65`,
    l3: dateStr(claims.nbf),
    tone: "green",
  });
  stamps.push({
    kind: "LOGGED",
    l1: `LEAF #${sample.leaf_index} ${DOT} TREE SIZE ${sample.checkpoint.size}`,
    l2: `RFC 6962 INCLUSION ${DOT} SLH-DSA CHECKPOINT`,
    l3: sample.checkpoint.origin.toUpperCase(),
    tone: "green",
  });
  for (const hop of claims.act_chain || []) {
    stamps.push({
      kind: "DELEGATED",
      l1: `${shortLineage(hop.from).toUpperCase()} → ${shortLineage(hop.to).toUpperCase()}`,
      l2: `GRANTED ${hop.granted.join(", ").toUpperCase()}`,
      l3: `EXPIRES ${dateStr(hop.exp)} ${DOT} DUAL-KEY SIGNED`,
      tone: "ink",
    });
  }
  if (!isValid) {
    stamps.push({
      kind: sample.verdict.reason.toUpperCase(),
      l1: `STATUS LIST ${claims.status.status_list.uri.toUpperCase()}`,
      l2: `IDX ${claims.status.status_list.idx} ${DOT} BIT SET ${DOT} FAILS CLOSED`,
      l3: `VERDICT: INVALID`,
      tone: "void",
    });
  }

  const W = 880,
    H = 560;
  const p = [];
  p.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${Math.round(W * 0.8)}" height="${Math.round(H * 0.8)}" font-family="${T.mono}">`,
  );
  p.push(sigilDefs.replace(/<svg[^>]*>|<\/svg>/g, ""));
  p.push(`<rect x="0" y="0" width="${W}" height="${H}" rx="14" fill="${T.card}" stroke="${T.line}"/>`);
  p.push(
    `<text x="${W / 2}" y="${H / 2 + 40}" text-anchor="middle" font-family="${T.display}" font-weight="800" font-size="150" fill="none" stroke="${T.ink}" stroke-opacity="0.04" transform="rotate(-14 ${W / 2} ${H / 2})">AINRA</text>`,
  );
  // header — same anatomy as the data page
  const M = 30,
    headH = 56;
  p.push(`<line x1="0" y1="${headH}" x2="${W}" y2="${headH}" stroke="${T.line}"/>`);
  p.push(
    `<svg x="${M}" y="12" width="34" height="34" viewBox="0 0 112 112"><use href="#ainra-sigil"/></svg>` +
      `<text x="${M + 44}" y="28" font-weight="700" font-size="13" letter-spacing="2" fill="${T.ink}">ENDORSEMENTS &amp; LOG</text>` +
      `<text x="${M + 44}" y="43" font-size="8.5" letter-spacing="1.2" fill="${T.muted}">${stamps.length} STAMPS ${DOT} EVERY EVENT SIGNED ${DOT} ANCHORED TO THE TRANSPARENCY LOG</text>`,
  );
  p.push(
    `<text x="${W - M}" y="26" text-anchor="end" font-size="10.5" letter-spacing="1.2" fill="${T.muted}">DOC AP-${docCode}</text>` +
      `<text x="${W - M}" y="43" text-anchor="end" font-size="9" letter-spacing="2" fill="${T.green}">SPECIMEN</text>`,
  );

  // stamps — a 2-column grid of inked entry stamps at slight alternating rotations (uses the wide format)
  const gx = M,
    gTop = headH + 22;
  const cols = 2;
  const gap = 20;
  const sw = (W - M * 2 - gap) / cols;
  const sh = 82;
  const rowGap = 18;
  stamps.forEach((s, i) => {
    const col = i % cols,
      row = Math.floor(i / cols);
    const sx = gx + col * (sw + gap);
    const sy = gTop + row * (sh + rowGap);
    const rot = (i % 2 === 0 ? -0.8 : 0.8) + (col === 1 ? 0.4 : 0);
    const stroke = s.tone === "green" ? T.green : s.tone === "void" ? T.muted : T.ink;
    p.push(`<g transform="rotate(${rot} ${sx + sw / 2} ${sy + sh / 2})">`);
    p.push(
      `<rect x="${sx}" y="${sy}" width="${sw}" height="${sh}" rx="8" fill="none" stroke="${stroke}" stroke-width="1.7" stroke-opacity="0.85"/>`,
    );
    p.push(
      `<rect x="${sx + 2}" y="${sy + 2}" width="${sw - 4}" height="${sh - 4}" rx="7" fill="none" stroke="${stroke}" stroke-width="0.5" stroke-opacity="0.4"/>`,
    );
    p.push(
      `<text x="${sx + 18}" y="${sy + 26}" font-size="14" font-weight="700" letter-spacing="2.4" fill="${stroke}">${esc(s.kind)}</text>`,
    );
    if (s.tone === "void") {
      p.push(
        `<line x1="${sx + 15}" y1="${sy + 21}" x2="${sx + 18 + s.kind.length * 10.5 + 6}" y2="${sy + 21}" stroke="${stroke}" stroke-width="1.6"/>`,
      );
    }
    p.push(
      `<text x="${sx + sw - 16}" y="${sy + 26}" text-anchor="end" font-size="9" letter-spacing="0.8" fill="${T.muted}">${esc(s.l3)}</text>`,
    );
    p.push(
      `<text x="${sx + 18}" y="${sy + 50}" font-size="11.5" letter-spacing="0.8" fill="${T.ink}">${esc(s.l1)}</text>`,
    );
    p.push(
      `<text x="${sx + 18}" y="${sy + 68}" font-size="9.5" letter-spacing="0.8" fill="${T.muted}">${esc(s.l2)}</text>`,
    );
    p.push(`</g>`);
  });

  // footer anchor — the real checkpoint root (the modern CHAIN HEAD)
  const fy = H - 46;
  p.push(`<line x1="${M}" y1="${fy}" x2="${W - M}" y2="${fy}" stroke="${T.line}" stroke-dasharray="2 3"/>`);
  p.push(
    `<text x="${M}" y="${fy + 20}" font-size="9" letter-spacing="1.4" fill="${T.muted}">CHECKPOINT ROOT</text>` +
      `<text x="${M + 140}" y="${fy + 20}" font-size="11" letter-spacing="0.6" fill="${isValid ? T.green : T.muted}">${esc(sample.checkpoint.root)}</text>`,
  );
  p.push(`</svg>`);
  return p.join("\n");
}

function main() {
  const sigilDefs = extractSigilDefs();
  const files = fs.readdirSync(DATA_DIR).filter((f) => f.endsWith(".json"));
  if (!files.length) {
    console.error(`no sample-*.json found in ${DATA_DIR} — run the sample_passport example first`);
    process.exit(1);
  }
  const rendered = [];
  for (const f of files) {
    const sample = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), "utf8"));
    const sides = [
      ["cover", renderCover(sample, sigilDefs)],
      ["data", renderCard(sample, sigilDefs)],
      ["stamps", renderStamps(sample, sigilDefs)],
    ];
    const sideFiles = {};
    for (const [side, svg] of sides) {
      const outName = `passport-${sample.kind}-${side}.svg`;
      fs.writeFileSync(path.join(OUT_DIR, outName), svg);
      sideFiles[side] = outName;
    }
    // keep the old single-file name pointing at the data page so existing references don't break
    fs.writeFileSync(path.join(OUT_DIR, `passport-${sample.kind}.svg`), sides[1][1]);
    rendered.push({ kind: sample.kind, sides: sideFiles, verdict: sample.verdict });
    console.log(`wrote samples/passport-${sample.kind}-{cover,data,stamps}.svg (verdict: ${JSON.stringify(sample.verdict)})`);
  }
  fs.writeFileSync(path.join(OUT_DIR, "manifest.json"), JSON.stringify({ rendered }, null, 2) + "\n");
}

main();
