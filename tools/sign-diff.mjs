// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make sign-diff — every signer's requests, checked by every verifier (D-071).
//
// `make diff` holds three VERIFIERS to one answer on requests the Rust core signed. It says nothing about the other
// signers: `signPresentation` in TypeScript and `sign_presentation` in Python build the signature base themselves,
// and a signer that covers the wrong bytes produces requests only its own verifier accepts. So here each of those
// signers signs fresh requests under a key that has never existed — a GET, a POST with a body, a path with a query
// under a mixed-case method and authority, and a request another signer signed first — and all three verifiers
// (ainra-core, @ainra/sdk, the Python package) must accept every one, with the nonce and timestamp the signer used.
//
//   node tools/sign-diff.mjs              2 signers × 3 verifiers
//   node tools/sign-diff.mjs --negative   one byte of every signature flipped: every verifier MUST refuse every one
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { signPresentation, runPresentationVector } from "../packages/sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const NEGATIVE = process.argv.includes("--negative");
const sdkRequire = createRequire(new URL("../packages/sdk-ts/package.json", import.meta.url));
const load = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await load("@noble/post-quantum/ml-dsa");
const { ed25519 } = await load("@noble/curves/ed25519");
const b64u = (u) => Buffer.from(u).toString("base64url");
const stable = (x) => JSON.stringify(x, Object.keys(x).sort());
const dir = mkdtempSync(join(tmpdir(), "ainra-sign-diff-"));

// ── signer 1: the Python package ─────────────────────────────────────────────────────────────────────────────────
console.log(execFileSync("python3", ["tools/sign-diff-emit.py", dir], {
  cwd: ROOT, encoding: "utf8", env: { ...process.env, PYTHONPATH: join(ROOT, "packages/sdk-py") },
}).trim());

// ── signer 2: @ainra/sdk ─────────────────────────────────────────────────────────────────────────────────────────
{
  const edSk = ed25519.utils.randomPrivateKey();
  const ml = ml_dsa65.keygen(randomBytes(32));
  const instanceSign = (msg) => ({ ed25519: ed25519.sign(msg, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, msg) });
  const ikey = { ed25519: b64u(ed25519.getPublicKey(edSk)), mldsa65: b64u(ml.publicKey) };
  const now = Math.floor(Date.now() / 1000);
  const ref = `sha-256=:${Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => i)).toString("base64")}:`;
  const other = {
    "signature-input": 'sig1=("@authority");created=1;expires=2;keyid="k";alg="ed25519";tag="web-bot-auth"',
    signature: `sig1=:${Buffer.alloc(64).toString("base64")}:`,
  };
  const cases = [
    ["get", "GET", "/orders", null, {}],
    ["post-with-body", "POST", "/orders", Buffer.from('{"sku":"A-1","qty":2}'), {}],
    ["query-and-case", "get", "/Search?q=a%20b&page=2", null, {}],
    ["beside-another-signer", "GET", "/orders", null, other],
  ];
  for (const [i, [name, method, path, body, prior]] of cases.entries()) {
    const headers = { "x-ainra-passport": ref, ...prior };
    Object.assign(headers, await signPresentation({
      req: { method, authority: "Shop.Example:8443", path, headers, body: body ?? undefined },
      keyid: "i-signdiff", nonce: `ts-${i}`, created: now, instanceSign,
    }));
    writeFileSync(join(dir, `ts-${name}.json`), JSON.stringify({
      name: `ts-${name}`,
      request: { method, authority: "Shop.Example:8443", path, headers: Object.entries(headers), body_b64u: body ? b64u(body) : null },
      instance: { iid: "i-signdiff", ikey },
      now, max_age_secs: 300, seen_nonces: [],
      expect: { created: now, nonce: `ts-${i}`, ok: true },
    }));
  }
  console.log(`typescript signed ${cases.length} requests`);
}

// ── the negative control: one flipped byte in AINRA's member of every signature ──────────────────────────────────
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
if (NEGATIVE) {
  for (const f of files) {
    const v = JSON.parse(readFileSync(join(dir, f), "utf8"));
    for (const h of v.request.headers) {
      if (h[0].toLowerCase() !== "signature") continue;
      h[1] = h[1].replace(/ainra=:([A-Za-z0-9+/=]+):/, (_, b) => {
        const raw = Buffer.from(b, "base64"); raw[100] ^= 1; return `ainra=:${raw.toString("base64")}:`;
      });
    }
    v.expect = { ok: false, reason: "presentation_sig_invalid" };
    writeFileSync(join(dir, f), JSON.stringify(v));
  }
  console.log("negative control: one byte flipped in every signature — every verifier must now refuse every request");
}

// ── three verifiers ──────────────────────────────────────────────────────────────────────────────────────────────
let failures = 0;
const vectors = files.map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")));
// ainra-core: its own check compares each file's `expect` with what verify_presentation returns.
try {
  execFileSync("cargo", ["run", "--release", "-q", "-p", "ainra-vector-gen", "--", "--check-presentation", dir], { cwd: ROOT, stdio: "pipe" });
  console.log(`  ok    ainra-core    ${vectors.length}/${vectors.length}`);
} catch (e) {
  failures++;
  console.error(`  ✗     ainra-core    ${String(e.stderr ?? e).trim().split("\n").slice(-3).join(" | ")}`);
}
// @ainra/sdk
{
  const wrong = vectors.filter((v) => stable(runPresentationVector(v)) !== stable(v.expect));
  if (wrong.length) { failures++; for (const v of wrong) console.error(`  ✗     @ainra/sdk    ${v.name}: ${JSON.stringify(runPresentationVector(v))}`); }
  else console.log(`  ok    @ainra/sdk    ${vectors.length}/${vectors.length}`);
}
// the Python package
{
  const out = execFileSync("python3", ["-m", "ainra._vector_runner", "presentation", dir], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, PYTHONPATH: join(ROOT, "packages/sdk-py") },
  });
  const got = new Map(out.split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("\t")), l.slice(l.indexOf("\t") + 1)]));
  const wrong = vectors.filter((v) => got.get(v.name) !== stable(v.expect));
  if (wrong.length) { failures++; for (const v of wrong) console.error(`  ✗     python        ${v.name}: ${got.get(v.name)}`); }
  else console.log(`  ok    python        ${vectors.length}/${vectors.length}`);
}
rmSync(dir, { recursive: true, force: true });

if (failures) { console.error(`\nSIGN-DIFF FAILED${NEGATIVE ? " (negative control: a verifier accepted a corrupted signature, or refused it for another reason)" : ""}`); process.exit(1); }
console.log(NEGATIVE
  ? "\nnegative control OK: every verifier refused every corrupted signature as presentation_sig_invalid."
  : `\nSIGN-DIFF OK: ${vectors.length} requests signed by Python and TypeScript; ainra-core, @ainra/sdk and the Python package accept every one.`);
