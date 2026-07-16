// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA local test console — the M1/M2 successor of the v0 prototype's `server.ts` console.
//
// Zero dependencies (node:http only). Serves the landing page, the sample passport book, and a LIVE verify API:
// every verdict shown in the browser is produced by the real TypeScript verifier (`packages/sdk-ts`), never
// precomputed or mocked. The tamper switches mutate the *presentation* (or, for schema demos, the claim bytes) and
// re-run the verifier, so each of the closed failure reasons can be demonstrated against a genuinely-signed
// credential. Local only: binds 127.0.0.1, zero telemetry, no outbound calls.
//
// Run: `make console`  (or: node apps/console/server.mjs [port])

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verify } from "../../packages/sdk-ts/dist/index.js";
import { b64uDecode } from "../../packages/sdk-ts/dist/crypto.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const PORT = Number(process.argv[2] || 4870);

// ── sample loading ─────────────────────────────────────────────────────────────────────────────────────────────
const KINDS = ["valid", "delegated", "revoked"];
function loadSample(kind) {
  const p = path.join(ROOT, "samples/data", `sample-${kind}.json`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

/** Convert a sample JSON (the sample_passport example's output) into the SDK's Presentation + TrustAnchors. */
function toPresentation(sample) {
  const claims = JSON.parse(sample.claims);
  const registrar = claims.iss.split(":")[2]; // did:ainra:{registrar}:...
  const anchors = {
    [registrar]: {
      issuerKey: {
        ed25519: b64uDecode(sample.issuer_pub.ed25519),
        mldsa65: b64uDecode(sample.issuer_pub.mldsa65),
      },
      logRootKey: b64uDecode(sample.root_pub_slh),
    },
  };
  const pres = {
    claims: new TextEncoder().encode(sample.claims),
    issuerSig: {
      ed25519: b64uDecode(sample.issuer_sig.ed25519),
      mldsa65: b64uDecode(sample.issuer_sig.mldsa65),
    },
    now: sample.verify_now,
    // M2: one key per chain PARTY (hops + 1), plus a log-inclusion proof per hop.
    chainKeys: (sample.chain_keys || []).map((k) => ({
      ed25519: b64uDecode(k.ed25519),
      mldsa65: b64uDecode(k.mldsa65),
    })),
    hopProofs: (sample.hop_proofs || []).map((hp) => ({
      leafIndex: hp.leaf_index,
      proof: hp.proof.map(b64uDecode),
    })),
    statusBits: sample.status_bits.slice(),
    statusIssuedAt: sample.verify_now - 5,
    freshness: "F3",
    checkpoint: {
      origin: sample.checkpoint.origin,
      size: sample.checkpoint.size,
      root: b64uDecode(sample.checkpoint.root),
      rootB64: sample.checkpoint.root,
    },
    // The samples sign checkpoints in root mode (the delegate mode is exercised by the conformance vectors).
    checkpointSig: { mode: "root", slh: b64uDecode(sample.checkpoint_sig) },
    leafIndex: sample.leaf_index,
    inclusionProof: sample.inclusion_proof.map(b64uDecode),
    mandatePath: [],
    mandateProofs: [],
    mandateRevocations: new Set(),
  };
  return { pres, anchors, claims };
}

// ── tamper switches — each mutates the presentation (or claim bytes) then the REAL verifier decides ────────────
const TAMPERS = {
  none: {
    label: "As presented",
    hint: "no tampering — the credential exactly as issued",
    apply: () => {},
  },
  strip_pq: {
    label: "Strip the ML-DSA-65 signature",
    hint: "hybrid means BOTH — a missing post-quantum signature is a downgrade attempt",
    apply: ({ pres }) => {
      pres.issuerSig = { ...pres.issuerSig, mldsa65: new Uint8Array(0) };
    },
  },
  corrupt_sig: {
    label: "Flip one byte of the Ed25519 signature",
    hint: "present but wrong — cryptographic verification fails",
    apply: ({ pres }) => {
      const s = Uint8Array.from(pres.issuerSig.ed25519);
      s[0] ^= 0xff;
      pres.issuerSig = { ...pres.issuerSig, ed25519: s };
    },
  },
  time_travel: {
    label: "Verify after expiry",
    hint: "now > exp",
    apply: ({ pres, claims }) => {
      pres.now = claims.exp + 3600;
      pres.statusIssuedAt = pres.now - 5;
    },
  },
  too_early: {
    label: "Verify before nbf",
    hint: "now < nbf",
    apply: ({ pres, claims }) => {
      pres.now = Math.max(0, claims.nbf - 3600);
      pres.statusIssuedAt = pres.now - 5;
    },
  },
  revoke: {
    label: "Set the status-list bit",
    hint: "the registrar revoked this lineage",
    apply: ({ pres, claims }) => {
      pres.statusBits = pres.statusBits.slice();
      pres.statusBits[claims.status.status_list.idx] = true;
    },
  },
  stale: {
    label: "Serve day-old status material",
    hint: "older than the freshness class allows — fails closed",
    apply: ({ pres }) => {
      pres.statusIssuedAt = pres.now - 90_000; // > F3's 24h
    },
  },
  drop_proof: {
    label: "Drop the Merkle inclusion proof",
    hint: "logged-before-valid: no proof, no VALID",
    apply: ({ pres }) => {
      pres.inclusionProof = [];
    },
  },
  tamper_checkpoint: {
    label: "Alter the signed checkpoint",
    hint: "tree size +1 — the SLH-DSA signature no longer matches",
    apply: ({ pres }) => {
      pres.checkpoint = { ...pres.checkpoint, size: pres.checkpoint.size + 1 };
    },
  },
  unknown_registrar: {
    label: "Present to a verifier that doesn't trust this registrar",
    hint: "the issuer is not in the verifier's accreditation directory",
    apply: (ctx) => {
      const entries = Object.entries(ctx.anchors);
      ctx.anchors = { "registrar-99": entries[0][1] };
    },
  },
  forbidden_field: {
    label: "Smuggle a `score` field into the claims",
    hint: "the passport is neutral identity — score/price/PII are rejected at the schema gate",
    apply: (ctx) => {
      const mutated = { ...JSON.parse(new TextDecoder().decode(ctx.pres.claims)), score: 99 };
      ctx.pres.claims = new TextEncoder().encode(JSON.stringify(sortKeys(mutated)));
    },
  },
  bad_name: {
    label: "Uppercase the subject name",
    hint: "the name grammar is lowercase-only (homoglyph defense)",
    apply: (ctx) => {
      const mutated = JSON.parse(new TextDecoder().decode(ctx.pres.claims));
      mutated.sub = mutated.sub.toUpperCase();
      ctx.pres.claims = new TextEncoder().encode(JSON.stringify(sortKeys(mutated)));
    },
  },
  swap_party_key: {
    label: "Swap a chain party key (delegated only)",
    hint: "a hop's counter-signature no longer verifies against the claimed delegatee",
    onlyFor: "delegated",
    apply: ({ pres }) => {
      if (pres.chainKeys.length >= 2) pres.chainKeys[1] = pres.chainKeys[0];
    },
  },
  drop_party_key: {
    label: "Withhold a chain party key (delegated only)",
    hint: "one key per party (hops + 1) is the verifier-input contract",
    onlyFor: "delegated",
    apply: ({ pres }) => {
      pres.chainKeys = pres.chainKeys.slice(0, -1);
    },
  },
  drop_hop_proof: {
    label: "Drop a delegation-hop log proof (delegated only)",
    hint: "logged-before-valid applies to delegation events too — a hop with no inclusion proof is not logged",
    onlyFor: "delegated",
    apply: ({ pres }) => {
      if (pres.hopProofs.length > 0) pres.hopProofs[pres.hopProofs.length - 1].proof = [];
    },
  },
};

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === "object") {
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, sortKeys(v[k])]),
    );
  }
  return v;
}

// ── http ───────────────────────────────────────────────────────────────────────────────────────────────────────
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".png": "image/png",
};

function sendFile(res, absPath) {
  if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }
  res.writeHead(200, { "content-type": MIME[path.extname(absPath)] || "application/octet-stream" });
  res.end(fs.readFileSync(absPath));
}

function sendJson(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj, null, 2));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const p = url.pathname;
  try {
    if (p === "/" || p === "/index.html") return sendFile(res, path.join(ROOT, "apps/console/index.html"));
    if (p === "/landing") return sendFile(res, path.join(ROOT, "apps/landing/index.html"));
    if (p.startsWith("/samples/")) {
      const rel = path.normalize(p.slice("/samples/".length));
      if (rel.startsWith("..")) return sendJson(res, 400, { error: "bad path" });
      return sendFile(res, path.join(ROOT, "samples", rel));
    }
    if (p === "/api/samples") {
      const out = KINDS.map((kind) => {
        const s = loadSample(kind);
        const claims = JSON.parse(s.claims);
        return {
          kind,
          sub: claims.sub,
          tier: claims.tier,
          verdict: s.verdict,
          sides: {
            cover: `/samples/passport-${kind}-cover.svg`,
            data: `/samples/passport-${kind}-data.svg`,
            stamps: `/samples/passport-${kind}-stamps.svg`,
          },
        };
      });
      const tampers = Object.entries(TAMPERS).map(([id, t]) => ({
        id,
        label: t.label,
        hint: t.hint,
        onlyFor: t.onlyFor || null,
      }));
      return sendJson(res, 200, { samples: out, tampers });
    }
    if (p === "/api/verify" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        try {
          const { kind, tamper } = JSON.parse(body || "{}");
          if (!KINDS.includes(kind)) return sendJson(res, 400, { error: `unknown kind ${kind}` });
          const t = TAMPERS[tamper || "none"];
          if (!t) return sendJson(res, 400, { error: `unknown tamper ${tamper}` });
          const ctx = toPresentation(loadSample(kind));
          t.apply(ctx);
          const t0 = process.hrtime.bigint();
          const verdict = verify(ctx.pres, ctx.anchors); // THE real verifier — the verdict is computed, never canned
          const micros = Number(process.hrtime.bigint() - t0) / 1000;
          return sendJson(res, 200, { kind, tamper: tamper || "none", verdict, verify_micros: Math.round(micros) });
        } catch (e) {
          return sendJson(res, 500, { error: String(e && e.message ? e.message : e) });
        }
      });
      return;
    }
    return sendJson(res, 404, { error: "not found" });
  } catch (e) {
    return sendJson(res, 500, { error: String(e && e.message ? e.message : e) });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`AINRA console  http://127.0.0.1:${PORT}/          (book viewer + live verify)`);
  console.log(`landing page   http://127.0.0.1:${PORT}/landing`);
  console.log(`sample gallery http://127.0.0.1:${PORT}/samples/index.html`);
});
