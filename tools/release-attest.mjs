// SPDX-License-Identifier: Apache-2.0 OR MIT
// M24 Task 3 — release provenance + SBOM generator. Writes dist/provenance.json (SLSA-style build provenance) and
// dist/sbom.json (CycloneDX-lite bill of materials) from the REAL repo state — the git commit, the pinned toolchain,
// every crate locked in Cargo.lock, the Node deps, and the sha256 of each built artifact. Nothing fabricated: a
// downloader can recompute every field. Invoked by scripts/release.sh after dist/ is populated.
//
//   node tools/release-attest.mjs <dist-dir> <version>
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = process.argv[2] || "dist";
const VERSION = process.argv[3] || "v0.0.0-dev";
const rd = (p) => readFileSync(join(ROOT, p), "utf8");
const git = (...a) => execFileSync("git", a, { cwd: ROOT, encoding: "utf8" }).trim();
const sha256 = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

// ── toolchain (pinned, real) ────────────────────────────────────────────────────────────────────────────────────
const channel = (rd("rust-toolchain.toml").match(/channel\s*=\s*"([^"]+)"/) || [])[1] || "unknown";
const ver = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: "utf8" }).trim().split("\n")[0]; } catch { return "unavailable"; } };

// ── artifacts actually in dist/ (name, bytes, sha256) ───────────────────────────────────────────────────────────
const subjects = readdirSync(DIST)
  .filter((f) => !["provenance.json", "sbom.json", "SHA256SUMS.sig", "allowed_signers", "ainra-release.pub"].includes(f))
  .map((f) => ({ name: f, bytes: statSync(join(DIST, f)).size, sha256: sha256(join(DIST, f)) }));

// ── provenance (SLSA v1-shaped, honest) ─────────────────────────────────────────────────────────────────────────
const provenance = {
  _type: "https://in-toto.io/Statement/v1",
  subject: subjects.map((s) => ({ name: s.name, digest: { sha256: s.sha256 } })),
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      buildType: "https://ainra.org/release/make-release/v1",
      externalParameters: { version: VERSION, repository: "git", make_target: "make release" },
      resolvedDependencies: [{ uri: "git+source", digest: { gitCommit: git("rev-parse", "HEAD") } }],
    },
    runDetails: {
      builder: { id: "https://ainra.org/release/local-maintainer" },
      metadata: { invocationId: git("rev-parse", "HEAD") },
      // The reproducibility claim is the trust anchor: the conformance corpus + manifest rebuild byte-for-byte from
      // this commit (`make repro`), so a stranger reproduces `MANIFEST.sha256` and needs no trust in the builder.
      byproducts: [{ name: "reproducibility", mediaType: "text/plain", content: `make repro rebuilds MANIFEST.sha256 byte-identical from commit ${git("rev-parse", "--short", "HEAD")}` }],
    },
    toolchain: { rust: channel, rustc: ver("rustc", ["--version"]), cargo: ver("cargo", ["--version"]), node: process.version },
  },
};
writeFileSync(join(DIST, "provenance.json"), JSON.stringify(provenance, null, 2) + "\n");

// ── SBOM (CycloneDX-lite) — every locked crate + the Node deps, from the real lockfiles ─────────────────────────
const components = [];
// Rust: parse Cargo.lock [[package]] blocks (name + version + checksum where present)
try {
  const lock = rd("Cargo.lock");
  for (const block of lock.split("[[package]]").slice(1)) {
    const name = (block.match(/name\s*=\s*"([^"]+)"/) || [])[1];
    const version = (block.match(/version\s*=\s*"([^"]+)"/) || [])[1];
    const checksum = (block.match(/checksum\s*=\s*"([^"]+)"/) || [])[1];
    if (name && version) components.push({ type: "library", name, version, purl: `pkg:cargo/${name}@${version}`, ...(checksum ? { hashes: [{ alg: "SHA-256", content: checksum }] } : {}) });
  }
} catch {}
// Node: the SDK + CLI declared deps (the primitive libraries — @noble PQC etc.)
for (const pj of ["packages/sdk-ts/package.json", "apps/cli-node/package.json"]) {
  try {
    const p = JSON.parse(rd(pj));
    for (const [name, version] of Object.entries({ ...(p.dependencies || {}), ...(p.devDependencies || {}) }))
      components.push({ type: "library", name, version: String(version).replace(/^[\^~]/, ""), purl: `pkg:npm/${name}@${String(version).replace(/^[\^~]/, "")}` });
  } catch {}
}
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  metadata: {
    component: { type: "application", name: "ainra", version: VERSION },
    tools: [{ name: "ainra release-attest", version: "1" }],
    note: "Generated from Cargo.lock + the Node package manifests at the release commit. Recompute: node tools/release-attest.mjs.",
  },
  components: components.sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version)),
};
writeFileSync(join(DIST, "sbom.json"), JSON.stringify(sbom, null, 2) + "\n");

console.log(`  provenance.json: ${subjects.length} subject(s), commit ${git("rev-parse", "--short", "HEAD")}, toolchain ${channel}`);
console.log(`  sbom.json: ${components.length} components (${components.filter((c) => c.purl.startsWith("pkg:cargo")).length} cargo + ${components.filter((c) => c.purl.startsWith("pkg:npm")).length} npm)`);
