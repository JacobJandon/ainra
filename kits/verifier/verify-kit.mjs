// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRA External Verifier Kit — become "external verifier #N".
//
// This runs a stranger's OWN machine against a set of published AINRA artifacts (a directory + roots + bundles) and
// proves, using ONLY the published @ainra/sdk, that:
//   1. a genuine passport verifies VALID with the ROOT DARK (we hold only the directory + roots, never the root key),
//   2. a revoked passport verifies INVALID with reason `revoked`,
//   3. a FORGED all-clear status verifies INVALID with reason `stale_status` (the presenter cannot un-revoke it).
// It then emits `verifier-attestation.json` — signed by the verifier's own fresh Ed25519 key — recording their
// public key, the SHA-256 of every artifact they checked, their verdicts, the SDK version, and a timestamp. We can
// collect that attestation as evidence WITHOUT trusting the verifier's word: `check-attestation.mjs` verifies the
// signature, recomputes the artifact hashes against the canonical published set, and confirms the verdicts.
//
//   node verify-kit.mjs --artifacts <dir> [--now <unix>] [--out verifier-attestation.json]
//                       [--challenge-dir <dir>]   ← REQUIRED to count as an external verifier (see below)
//
// EXECUTION BINDING (--challenge-dir): the checks above run against a STATIC corpus whose correct verdicts are public,
// so their presence in an attestation proves agreement, NOT that you ran anything. To make the attestation actually
// require verification, the maintainer hands you a FRESH challenge corpus (mint-challenge.mjs): K bundles whose
// revocation state is a secret coin flip. This kit verifies each one root-dark and records your verdicts; you can
// only report the correct set BY VERIFYING. The maintainer checks them against a private answer key (a forger who
// never ran a verifier must guess all K → 2^-K). Without --challenge-dir the attestation is conformance-only and does
// NOT count as an external verifier.
//
// The kit imports nothing but @ainra/sdk (the public Verifier) and Node built-ins. No internal crates, no telemetry.

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { deflateSync } from "node:zlib";
import { Verifier } from "@ainra/sdk";

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const dir = arg("artifacts", new URL("./sample-artifacts", import.meta.url).pathname);
const outPath = arg("out", "verifier-attestation.json");
// A maintainer-issued, single-use CHALLENGE (nonce) the verifier signs into the attestation. Without it, a body of
// all-public data could be hand-authored or replayed; binding to a fresh challenge the collector issued makes the
// attestation un-pre-manufacturable and non-replayable. Distinctness of *operators* is still out of band (the
// maintainer issues one challenge per separately-vetted party) — the crypto proves execution + freshness, not Sybil.
const challenge = arg("challenge", "");
const challengeDir = arg("challenge-dir", ""); // a FRESH maintainer-minted corpus (mint-challenge.mjs); binds execution
const read = (f) => readFileSync(`${dir}/${f}`, "utf8");
const readJson = (f) => JSON.parse(read(f));
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
// FULL recursive canonical JSON — sorts keys at EVERY level and includes ALL of them. (An array replacer to
// JSON.stringify is a per-level allowlist that silently DROPS nested keys, so the signature would not cover
// artifacts_sha256 or verdicts — that footgun is why this is spelled out.)
function canonicalJSON(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}

// `now` for freshness: the sample bundles carry their issued-at in meta.json; a live run passes --now (real time).
let now = Number(arg("now", "0"));
if (!now) {
  try { now = readJson("meta.json").now; } catch { now = Math.floor(Date.now() / 1000); }
}

const directory = readJson("directory.json");
const roots = readJson("roots.json");
const bundleValid = readJson("bundle-valid.json");
const bundleRevoked = readJson("bundle-revoked.json");

// Build the verifier ROOT DARK — it holds only the published directory + the two root public keys, never a secret.
const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
if (!verifier) {
  console.error("FAIL: the directory is not trust-anchored by the given roots (untrusted directory)");
  process.exit(2);
}

// Forge an all-clear status from the revoked bundle (the attack every verifier must reject): rewrite the status
// bitmap to all-zero (nobody revoked) + re-stamp it fresh, WITHOUT re-signing. Standard zlib; self-contained.
function forgeAllClear(bundle) {
  const forged = structuredClone(bundle);
  const nBytes = Math.ceil(Number(bundle.status_len) / 8);
  forged.status_list = deflateSync(Buffer.alloc(nBytes)).toString("base64url");
  forged.status_issued_at = now;
  forged.freshness = "F1";
  return forged;
}
const bundleForged = forgeAllClear(bundleRevoked);

// Run the three checks with the real SDK.
const vValid = verifier.verify(bundleValid, now);
const vRevoked = verifier.verify(bundleRevoked, now);
const vForged = verifier.verify(bundleForged, now);

const checks = [
  { name: "genuine passport (root dark)", expect: "valid", got: vValid },
  { name: "revoked passport", expect: "invalid:revoked", got: vRevoked },
  { name: "forged all-clear status", expect: "invalid:stale_status", got: vForged },
];
const asStr = (v) => (v.verdict === "valid" ? "valid" : `invalid:${v.reason}`);
let allPass = true;
console.log(`AINRA verifier kit — artifacts: ${dir} · now: ${now} · sdk-verify (root dark)\n`);
for (const c of checks) {
  const got = asStr(c.got);
  const ok = got === c.expect;
  allPass = allPass && ok;
  console.log(`  ${ok ? "✓" : "✗"} ${c.name} → ${got} (expected ${c.expect})`);
}
if (!allPass) {
  console.error("\nFAIL: a conformant AINRA verifier must produce all three verdicts above. No attestation written.");
  process.exit(1);
}

// ── EXECUTION BINDING — verify the maintainer's FRESH challenge corpus (the part a non-executor cannot fake) ────────
let challengeBlock = null; // { nonce, now, corpus_sha256, verdicts } when --challenge-dir is given
if (challengeDir) {
  const cread = (f) => readFileSync(`${challengeDir}/${f}`, "utf8");
  const cjson = (f) => JSON.parse(cread(f));
  const chal = cjson("challenge.json");
  if (challenge && chal.nonce !== challenge) {
    console.error(`\nFAIL: --challenge ${challenge} does not match the challenge corpus nonce ${chal.nonce}`);
    process.exit(2);
  }
  const croots = cjson("roots.json");
  const cverifier = Verifier.fromDirectoryB64(cjson("directory.json"), croots.root_ed25519, croots.root_slh);
  if (!cverifier) { console.error("\nFAIL: challenge directory not trust-anchored by its roots"); process.exit(2); }
  const cnow = Number(chal.now);
  console.log(`\nexecution binding — verifying ${chal.bundles.length} FRESH challenge bundles root-dark (nonce ${chal.nonce}):`);
  const cverdicts = chal.bundles.map((f) => {
    const v = asStr(cverifier.verify(cjson(f), cnow));
    console.log(`  · ${f} → ${v}`);
    return v;
  });
  // hash the WHOLE challenge corpus we verified (binds us to the maintainer's exact fresh bundles, not our own).
  const cfiles = ["directory.json", "roots.json", "challenge.json", ...chal.bundles];
  const ccorpus = Object.fromEntries(cfiles.map((f) => [f, sha256(cread(f))]));
  challengeBlock = { nonce: chal.nonce, now: cnow, corpus_sha256: ccorpus, verdicts: cverdicts };
} else {
  console.log("\n⚠ no --challenge-dir given: this attestation is CONFORMANCE-ONLY and will NOT count as an external");
  console.log("  verifier (the static verdicts above are public and could be asserted without running anything).");
}

// Emit a signed attestation. The verifier's OWN fresh Ed25519 key signs the body (standard node:crypto — no bespoke
// crypto). We collect it later without trusting their word: verify the signature, recompute the corpus hashes, and —
// decisively — check the challenge verdicts against a private answer key the verifier never saw.
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const body = {
  kind: "ainra/verifier-attestation/v1",
  challenge: challengeBlock ? challengeBlock.nonce : challenge, // the challenge this attestation answers
  execution_bound: challengeBlock !== null, // true only when a fresh challenge corpus was verified
  verifier_pubkey_spki_b64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  sdk: (() => {
    try {
      return JSON.parse(readFileSync(new URL("./node_modules/@ainra/sdk/package.json", import.meta.url), "utf8")).version;
    } catch {
      return "unknown";
    }
  })(),
  now,
  artifacts_sha256: {
    "directory.json": sha256(read("directory.json")),
    "roots.json": sha256(read("roots.json")),
    "bundle-valid.json": sha256(read("bundle-valid.json")),
    "bundle-revoked.json": sha256(read("bundle-revoked.json")),
  },
  verdicts: { valid: asStr(vValid), revoked: asStr(vRevoked), forged: asStr(vForged) },
  // the execution-bound evidence: our verdicts on the maintainer's fresh, unpublished challenge corpus.
  challenge_now: challengeBlock ? challengeBlock.now : null,
  challenge_corpus_sha256: challengeBlock ? challengeBlock.corpus_sha256 : null,
  challenge_verdicts: challengeBlock ? challengeBlock.verdicts : null,
};
const sig = edSign(null, Buffer.from(canonicalJSON(body)), privateKey).toString("base64");
const attestation = { body, sig_ed25519_b64: sig };
writeFileSync(outPath, JSON.stringify(attestation, null, 2) + "\n");

console.log(`\n✓ wrote a signed ${challengeBlock ? "EXECUTION-BOUND" : "conformance-only"} attestation → ${outPath}`);
console.log("  Send it to the AINRA maintainers; they verify it without trusting you:");
console.log("    node check-attestation.mjs --attestation " + outPath + " --challenge " + (challengeBlock ? challengeBlock.nonce : "<nonce>") + " --secret <the challenge answer key> --canonical " + dir);
